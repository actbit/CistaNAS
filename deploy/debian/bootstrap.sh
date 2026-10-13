#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "bootstrap.sh must run as root." >&2
    exit 1
fi

readonly INSTALL_ROOT="${1:?install root is required}"
readonly DEPLOY_USER="${2:?deployment user is required}"
SSH_ALLOW_FROM="${3:-}"
readonly CERT_SOURCE="${4:-}"
readonly KEY_SOURCE="${5:-}"
readonly GITHUB_REPOSITORY="${6:?GitHub repository is required}"
readonly SERVICE_SOURCE="${7:?service unit source is required}"
readonly UPDATE_SCRIPT_SOURCE="${8:?update script source is required}"
readonly UPDATE_SERVICE_SOURCE="${9:?update service source is required}"
readonly UPDATE_CHECK_SERVICE_SOURCE="${10:?update check service source is required}"
readonly UPDATE_CHECK_PATH_SOURCE="${11:?update check path source is required}"
readonly UPDATE_APPLY_PATH_SOURCE="${12:?update apply path source is required}"

if ! id "${DEPLOY_USER}" >/dev/null 2>&1; then
    echo "Deployment user does not exist: ${DEPLOY_USER}" >&2
    exit 1
fi
if [[ ! "${GITHUB_REPOSITORY}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    echo "Invalid GitHub repository: ${GITHUB_REPOSITORY}" >&2
    exit 1
fi
for source in "${SERVICE_SOURCE}" "${UPDATE_SCRIPT_SOURCE}" "${UPDATE_SERVICE_SOURCE}" "${UPDATE_CHECK_SERVICE_SOURCE}" "${UPDATE_CHECK_PATH_SOURCE}" "${UPDATE_APPLY_PATH_SOURCE}"; do
    [[ -s "${source}" ]] || { echo "Missing deployment file: ${source}" >&2; exit 1; }
done

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl jq nginx ufw

if ! getent group cistanas >/dev/null 2>&1; then
    groupadd --system cistanas
fi
if ! id cistanas >/dev/null 2>&1; then
    useradd --system --gid cistanas --home-dir /var/lib/cistanas --shell /usr/sbin/nologin cistanas
fi

install -d -o root -g root -m 0755 "${INSTALL_ROOT}"
install -d -o root -g root -m 0755 "${INSTALL_ROOT}/releases"
install -d -o cistanas -g cistanas -m 0750 /var/lib/cistanas
install -d -o cistanas -g cistanas -m 0750 /var/lib/cistanas/data
install -d -o root -g root -m 0750 /etc/cistanas
install -d -o root -g root -m 0755 /usr/local/libexec

if [[ ! -f /etc/cistanas/cistanas.env ]]; then
    printf '%s\n' \
        'ASPNETCORE_ENVIRONMENT=Production' \
        'ASPNETCORE_URLS=http://127.0.0.1:8080' \
        > /etc/cistanas/cistanas.env
fi
chown root:cistanas /etc/cistanas/cistanas.env
chmod 0640 /etc/cistanas/cistanas.env

if [[ ! -f /etc/cistanas/update.env ]]; then
    printf 'CISTANAS_GITHUB_REPOSITORY=%s\n' "${GITHUB_REPOSITORY}" > /etc/cistanas/update.env
fi
chown root:root /etc/cistanas/update.env
chmod 0600 /etc/cistanas/update.env

install -o root -g root -m 0644 "${SERVICE_SOURCE}" /etc/systemd/system/cistanas.service
install -o root -g root -m 0750 "${UPDATE_SCRIPT_SOURCE}" /usr/local/libexec/cistanas-update
install -o root -g root -m 0644 "${UPDATE_SERVICE_SOURCE}" /etc/systemd/system/cistanas-update.service
install -o root -g root -m 0644 "${UPDATE_CHECK_SERVICE_SOURCE}" /etc/systemd/system/cistanas-update-check.service
install -o root -g root -m 0644 "${UPDATE_CHECK_PATH_SOURCE}" /etc/systemd/system/cistanas-update-check.path
install -o root -g root -m 0644 "${UPDATE_APPLY_PATH_SOURCE}" /etc/systemd/system/cistanas-update-apply.path
systemctl disable --now cistanas-update.timer >/dev/null 2>&1 || true
rm -f /etc/systemd/system/cistanas-update.timer

if [[ -n "${CERT_SOURCE}" || -n "${KEY_SOURCE}" ]]; then
    if [[ -z "${CERT_SOURCE}" || -z "${KEY_SOURCE}" || ! -s "${CERT_SOURCE}" || ! -s "${KEY_SOURCE}" ]]; then
        echo "Both Origin certificate and key must be supplied." >&2
        exit 1
    fi
    install -o root -g root -m 0644 "${CERT_SOURCE}" /etc/cistanas/cloudflare-origin.crt
    install -o root -g root -m 0600 "${KEY_SOURCE}" /etc/cistanas/cloudflare-origin.key
fi

cloudflare_ip_file="$(mktemp)"
trap 'rm -f "${cloudflare_ip_file}"' EXIT
curl --fail --silent --show-error --retry 3 https://www.cloudflare.com/ips-v4 \
    | tr -d '\r' | sed '/^[[:space:]]*$/d' >> "${cloudflare_ip_file}"
curl --fail --silent --show-error --retry 3 https://www.cloudflare.com/ips-v6 \
    | tr -d '\r' | sed '/^[[:space:]]*$/d' >> "${cloudflare_ip_file}"
sort -u -o "${cloudflare_ip_file}" "${cloudflare_ip_file}"
[[ -s "${cloudflare_ip_file}" ]] || { echo "Cloudflare IP ranges are empty." >&2; exit 1; }

old_cloudflare_ip_file=/var/lib/cistanas/cloudflare-ips
if [[ -f "${old_cloudflare_ip_file}" ]]; then
    while IFS= read -r cidr; do
        [[ -z "${cidr}" ]] && continue
        ufw --force delete allow from "${cidr}" to any port 80 proto tcp >/dev/null 2>&1 || true
        ufw --force delete allow from "${cidr}" to any port 443 proto tcp >/dev/null 2>&1 || true
    done < "${old_cloudflare_ip_file}"
fi
ufw --force delete allow 80/tcp >/dev/null 2>&1 || true
ufw --force delete allow 443/tcp >/dev/null 2>&1 || true
ufw --force delete allow 'Nginx Full' >/dev/null 2>&1 || true
ufw --force delete allow 'Nginx HTTP' >/dev/null 2>&1 || true
ufw --force delete allow 'Nginx HTTPS' >/dev/null 2>&1 || true

if [[ -z "${SSH_ALLOW_FROM}" && -f /etc/cistanas/ssh-allow-from ]]; then
    SSH_ALLOW_FROM="$(< /etc/cistanas/ssh-allow-from)"
fi
if [[ -z "${SSH_ALLOW_FROM}" && -n "${SSH_CONNECTION:-}" ]]; then
    SSH_ALLOW_FROM="${SSH_CONNECTION%% *}"
fi
[[ -n "${SSH_ALLOW_FROM}" ]] || { echo "SSH allow-list is empty." >&2; exit 1; }

ssh_port=22
if command -v sshd >/dev/null 2>&1; then
    ssh_port="$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2; exit }')"
    ssh_port="${ssh_port:-22}"
fi
if [[ -f /etc/cistanas/ssh-allow-from && "$(< /etc/cistanas/ssh-allow-from)" != "${SSH_ALLOW_FROM}" ]]; then
    read -r -a old_ssh_sources <<< "$(< /etc/cistanas/ssh-allow-from)"
    for old_source in "${old_ssh_sources[@]}"; do
        ufw --force delete allow from "${old_source}" to any port "${ssh_port}" proto tcp >/dev/null 2>&1 || true
    done
fi
read -r -a ssh_sources <<< "${SSH_ALLOW_FROM}"
for source in "${ssh_sources[@]}"; do
    ufw allow from "${source}" to any port "${ssh_port}" proto tcp >/dev/null
done
while IFS= read -r cidr; do
    ufw allow from "${cidr}" to any port 80 proto tcp >/dev/null
    ufw allow from "${cidr}" to any port 443 proto tcp >/dev/null
done < "${cloudflare_ip_file}"
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw --force enable >/dev/null
install -o root -g root -m 0644 "${cloudflare_ip_file}" "${old_cloudflare_ip_file}"
printf '%s\n' "${SSH_ALLOW_FROM}" > /etc/cistanas/ssh-allow-from
chmod 0640 /etc/cistanas/ssh-allow-from

cat > /etc/nginx/conf.d/cistanas-map.conf <<'NGINX_MAP'
map $http_upgrade $cistanas_connection_upgrade { default upgrade; '' close; }
map $http_cf_connecting_ip $cistanas_client_ip { default $http_cf_connecting_ip; '' $remote_addr; }
NGINX_MAP

cat > /etc/nginx/snippets/cistanas-proxy.conf <<'NGINX_PROXY'
proxy_pass http://127.0.0.1:8080;
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $cistanas_client_ip;
proxy_set_header X-Forwarded-For $cistanas_client_ip;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $cistanas_connection_upgrade;
proxy_request_buffering off;
proxy_buffering off;
proxy_read_timeout 3600s;
proxy_send_timeout 3600s;
NGINX_PROXY

if [[ -s /etc/cistanas/cloudflare-origin.crt && -s /etc/cistanas/cloudflare-origin.key ]]; then
    cat > /etc/nginx/sites-available/cistanas <<'NGINX_TLS'
server { listen 80 default_server; listen [::]:80 default_server; server_name _; return 301 https://$host$request_uri; }
server {
    listen 443 ssl default_server; listen [::]:443 ssl default_server; server_name _;
    ssl_certificate /etc/cistanas/cloudflare-origin.crt;
    ssl_certificate_key /etc/cistanas/cloudflare-origin.key;
    ssl_protocols TLSv1.2 TLSv1.3; client_max_body_size 10g;
    location / { include /etc/nginx/snippets/cistanas-proxy.conf; }
}
NGINX_TLS
else
    echo "No Origin certificate; nginx will use HTTP only." >&2
    cat > /etc/nginx/sites-available/cistanas <<'NGINX_HTTP'
server { listen 80 default_server; listen [::]:80 default_server; server_name _; client_max_body_size 10g; location / { include /etc/nginx/snippets/cistanas-proxy.conf; } }
NGINX_HTTP
fi

rm -f /etc/nginx/sites-enabled/default
ln -sfn /etc/nginx/sites-available/cistanas /etc/nginx/sites-enabled/cistanas
nginx -t
systemctl daemon-reload
systemctl enable cistanas.service cistanas-update-check.path cistanas-update-apply.path
systemctl start cistanas-update-check.path cistanas-update-apply.path
systemctl enable --now nginx.service
systemctl reload nginx.service
echo "Native systemd deployment base is ready."
