#!/usr/bin/env bash
set -Eeuo pipefail

[[ ${EUID} -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
readonly domain="${CISTANAS_DOMAIN:?CISTANAS_DOMAIN is required}"
readonly email="${CISTANAS_EMAIL:?CISTANAS_EMAIL is required}"
readonly ssh_from="${CISTANAS_SSH_ALLOW_FROM:?CISTANAS_SSH_ALLOW_FROM is required}"
readonly deploy_user="${CISTANAS_DEPLOY_USER:-root}"
readonly repository="${CISTANAS_GITHUB_REPOSITORY:-actbit/CistaNAS}"
readonly dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly credentials=/root/cistanas-initial-admin.json
readonly settings=/root/cistanas-initial-settings.json

[[ ! -e /opt/cistanas/current && ! -e "$credentials" && ! -e "$settings" && ! -e /var/lib/cistanas/data/cista.db ]] || {
    echo 'Existing installation or initial credentials found; inspect the server before retrying.' >&2; exit 1;
}
id "$deploy_user" >/dev/null || { echo 'The deployment user must already exist.' >&2; exit 1; }
if ! command -v python3 >/dev/null; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3
fi
python3 - "$dir/appsettings.json.example" "$settings" "$credentials" "$domain" "$ssh_from" <<'PY'
import ipaddress, json, os, re, secrets, sys
source, settings, credentials, domain, ssh_from = sys.argv[1:]
if len(domain) > 253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', domain):
    sys.exit('Enter a valid lowercase domain name.')
try:
    for item in ssh_from.split():
        ipaddress.ip_network(item, strict=False)
except ValueError:
    sys.exit('CISTANAS_SSH_ALLOW_FROM must contain IP addresses or CIDRs.')
with open(source, encoding='utf-8') as f:
    config = json.load(f)
db = os.environ.get('CISTANAS_DB_PROVIDER', 'sqlite').lower()
storage = os.environ.get('CISTANAS_STORAGE_PROVIDER', 'local').lower()
connection = os.environ.get('CISTANAS_DB_CONNECTION', '')
bucket = os.environ.get('CISTANAS_S3_BUCKET', '')
region = os.environ.get('CISTANAS_S3_REGION', '')
endpoint = os.environ.get('CISTANAS_S3_ENDPOINT', '')
prefix = os.environ.get('CISTANAS_S3_PREFIX', '')
chunk_storage = os.environ.get('CISTANAS_CHUNK_STORAGE', 'local').lower()
access = os.environ.get('CISTANAS_S3_ACCESS_KEY', '')
secret = os.environ.get('CISTANAS_S3_SECRET_KEY', '')
conditional = {}
for field, variable in (('PutIfNoneMatch', 'CISTANAS_S3_PUT_IF_NONE_MATCH'),
                        ('PutIfMatch', 'CISTANAS_S3_PUT_IF_MATCH'),
                        ('DeleteIfMatch', 'CISTANAS_S3_DELETE_IF_MATCH')):
    value = os.environ.get(variable, 'true').lower()
    if value not in ('true', 'false'):
        sys.exit(variable + ' must be true or false.')
    conditional[field] = value == 'true'
password = os.environ.get('CISTANAS_ADMIN_PASSWORD', '') or 'Aa1' + secrets.token_urlsafe(32)
if db not in ('sqlite', 'postgresql', 's3') or storage not in ('local', 's3'):
    sys.exit('Supported DB providers: sqlite, postgresql, s3; storage: local, s3.')
if chunk_storage not in ('local', 'auto'):
    sys.exit('Chunk storage must be local or auto.')
if db == 'postgresql' and not connection:
    sys.exit('PostgreSQL requires a connection string.')
if db != 'postgresql' and connection:
    sys.exit('The database connection option is supported only for PostgreSQL.')
if db == 's3' and storage != 's3':
    sys.exit('An S3 database requires S3 storage.')
if storage == 's3' and not bucket:
    sys.exit('S3 storage requires a bucket name.')
if bool(access) != bool(secret):
    sys.exit('Supply both S3 access and secret keys, or neither for default credentials.')
if (access or secret) and storage != 's3':
    sys.exit('S3 keys require S3 storage.')
if any(not re.fullmatch(r'[A-Za-z0-9_+=/.-]+', x) for x in (access, secret) if x):
    sys.exit('S3 keys contain unsupported characters.')
if len(password) < 12 or len(password) > 256 or not any(c.islower() for c in password) or not any(c.isdigit() for c in password):
    sys.exit('Admin password must be 12–256 characters and contain lowercase and a digit.')
if access and os.path.exists('/etc/cistanas/aws.env'):
    sys.exit('Existing S3 credentials file found; inspect it before installing.')
config['AllowedHosts'] = domain + ';localhost'
config['CistaNas']['Jwt']['SigningKey'] = secrets.token_urlsafe(48)
config['CistaNas']['Auth']['DefaultAdminPassword'] = None
config['CistaNas']['Database']['Provider'] = db
config['CistaNas']['Database']['ConnectionString'] = connection or None
config['CistaNas']['Storage'].update({'Provider': storage, 'BucketOrContainer': bucket or None,
    'RegionOrConnectionString': region or None, 'EndpointOverride': endpoint or None,
    'PathPrefix': prefix or None, 'S3ConditionalRequests': conditional})
config['CistaNas']['Volume'] = {'ChunkStorage': chunk_storage}
admin = {'username': 'admin', 'password': password}
for path, obj in ((settings, config), (credentials, admin)):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(obj, f)
        f.write('\n')
if access:
    os.makedirs('/etc/cistanas', mode=0o750, exist_ok=True)
    fd = os.open('/etc/cistanas/aws.env', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write('AWS_ACCESS_KEY_ID=' + access + '\nAWS_SECRET_ACCESS_KEY=' + secret + '\n')
PY

export CISTANAS_INITIALIZE_ADMIN=1
bash "$dir/install.sh" "$deploy_user" "$settings" "$ssh_from" '' '' "$repository" "$domain" "$email"

# The application is reachable only on loopback; nginx still returns 503 externally.
python3 - "$credentials" <<'PY'
import json, sys, urllib.request
with open(sys.argv[1], encoding='utf-8') as f:
    body = f.read().encode('utf-8')
request = urllib.request.Request('http://127.0.0.1:8080/api/v1/auth/setup', data=body,
    headers={'Content-Type': 'application/json', 'Host': 'localhost'}, method='POST')
with urllib.request.urlopen(request, timeout=60) as response:
    if response.status != 200:
        sys.exit('Initial administrator creation failed.')
PY

printf '' > /etc/nginx/snippets/cistanas-initial-guard.conf
if ! nginx -t || ! systemctl reload nginx.service; then
    printf 'return 503;\n' > /etc/nginx/snippets/cistanas-initial-guard.conf
    exit 1
fi
rm -f "$settings"
printf '%s\n' 'CistaNAS is ready. Initial credentials are in /root/cistanas-initial-admin.json (root only).'
