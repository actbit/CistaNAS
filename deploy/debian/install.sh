#!/usr/bin/env bash
# Run from a checkout on the Debian host. See README.ja.md before use.
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo 'Run this script with sudo.' >&2
    exit 1
fi
if [[ $# -lt 2 || $# -gt 8 ]]; then
    echo 'Usage: sudo bash install.sh DEPLOY_USER SETTINGS_JSON [SSH_ALLOW_FROM] [ORIGIN_CERT ORIGIN_KEY] [GITHUB_REPOSITORY] [DOMAIN EMAIL]' >&2
    exit 2
fi
user=$1
settings=$2
ssh_from=${3:-}
cert=${4:-}
key=${5:-}
repository=${6:-actbit/CistaNAS}
domain=${7:-}
email=${8:-}
dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ -f "$settings" ]] || { echo 'Settings file not found.' >&2; exit 1; }
[[ ! -e /opt/cistanas/current ]] || { echo 'CistaNAS is already installed; use the update feature.' >&2; exit 1; }
case "$(uname -m)" in x86_64|aarch64|arm64) ;; *) echo 'Unsupported CPU architecture.' >&2; exit 1 ;; esac
if ! command -v python3 >/dev/null; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3
fi
python3 - "$settings" "$domain" "$email" "$cert" "$key" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as f:
    s = json.load(f)
c = s.get('CistaNas', {})
k = c.get('Jwt', {}).get('SigningKey', '')
if len(k.encode()) < 32 or k.startswith('REPLACE_WITH_'):
    sys.exit('Set a signing key of at least 32 bytes in the settings file.')
if c.get('DataRoot') != '/var/lib/cistanas/data':
    sys.exit('Set CistaNas:DataRoot to /var/lib/cistanas/data.')
domain, email, cert, key = sys.argv[2:]
if bool(domain) != bool(email):
    sys.exit('Specify both the domain and email for Let\'s Encrypt.')
if domain:
    import re
    if len(domain) > 253 or not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', domain):
        sys.exit('Enter a valid lowercase domain name.')
    if domain not in s.get('AllowedHosts', '').split(';'):
        sys.exit('Add the domain to AllowedHosts in the settings file.')
    if cert or key:
        sys.exit('Choose either Let\'s Encrypt or a supplied origin certificate.')
PY
bash "$dir/bootstrap.sh" /opt/cistanas "$user" "$ssh_from" "$cert" "$key" "$repository" \
    "$dir/cistanas.service" "$dir/cistanas-update.sh" "$dir/cistanas-update.service" \
    "$dir/cistanas-update-check.service" "$dir/cistanas-update-check.path" "$dir/cistanas-update-apply.path" "$domain" "$email"
if [[ -f /etc/cistanas/aws.env ]]; then
    chown root:cistanas /etc/cistanas/aws.env
    chmod 0640 /etc/cistanas/aws.env
fi
install -o root -g cistanas -m 0640 "$settings" /etc/cistanas/appsettings.Production.json
/usr/local/libexec/cistanas-update apply
systemctl enable cistanas.service
printf '%s\n' 'CistaNAS installation complete.'
