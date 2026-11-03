#!/usr/bin/env bash
# Download the versioned setup bundle and run its first-boot installer.
set -Eeuo pipefail

domain="${CISTANAS_DOMAIN:-}"
email="${CISTANAS_EMAIL:-}"
ssh_from="${CISTANAS_SSH_ALLOW_FROM:-}"
deploy_user="${CISTANAS_DEPLOY_USER:-${SUDO_USER:-root}}"
repository="${CISTANAS_GITHUB_REPOSITORY:-actbit/CistaNAS}"
db_provider="${CISTANAS_DB_PROVIDER:-sqlite}"
db_connection="${CISTANAS_DB_CONNECTION:-}"
storage="${CISTANAS_STORAGE_PROVIDER:-local}"
s3_bucket="${CISTANAS_S3_BUCKET:-}"
s3_region="${CISTANAS_S3_REGION:-}"
s3_endpoint="${CISTANAS_S3_ENDPOINT:-}"
s3_prefix="${CISTANAS_S3_PREFIX:-}"
chunk_storage="${CISTANAS_CHUNK_STORAGE:-local}"
s3_access="${CISTANAS_S3_ACCESS_KEY:-}"
s3_secret="${CISTANAS_S3_SECRET_KEY:-}"
admin_password="${CISTANAS_ADMIN_PASSWORD:-}"
s3_put_if_none_match="${CISTANAS_S3_PUT_IF_NONE_MATCH:-true}"
s3_put_if_match="${CISTANAS_S3_PUT_IF_MATCH:-true}"
s3_delete_if_match="${CISTANAS_S3_DELETE_IF_MATCH:-true}"

usage() {
    cat <<'HELP'
Usage: bash install.sh [--domain DOMAIN] [--email EMAIL] [--ssh-allow IP_OR_CIDR] [--user USER]
Missing values are requested from the terminal. For unattended installation supply
all three required options. The SSH user and public key must already be configured.
Optional: --db-provider sqlite|postgresql|s3, --db-connection[-file] VALUE,
--storage local|s3, --s3-bucket NAME, --s3-region REGION, --s3-endpoint URL,
--s3-prefix PREFIX, --chunk-storage local|auto,
--s3-access-key[-file] VALUE, --s3-secret-key[-file] VALUE,
--s3-put-if-none-match true|false, --s3-put-if-match true|false,
--s3-delete-if-match true|false, --admin-password[-file] VALUE.
File options read a secret from a local file.
HELP
}

while (($#)); do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --domain|--email|--ssh-allow|--user|--db-provider|--db-connection|--db-connection-file|--storage|--s3-bucket|--s3-region|--s3-endpoint|--s3-prefix|--chunk-storage|--s3-access-key|--s3-access-key-file|--s3-secret-key|--s3-secret-key-file|--s3-put-if-none-match|--s3-put-if-match|--s3-delete-if-match|--admin-password|--admin-password-file)
            option=$1
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { echo "Missing value for $option" >&2; exit 2; }
            value=$2
            if [[ "$option" == *-file ]]; then
                [[ -f "$value" && -r "$value" ]] || { echo "Cannot read secret file for $option" >&2; exit 2; }
                value=$(< "$value")
                [[ -n "$value" ]] || { echo "Empty secret file for $option" >&2; exit 2; }
            fi
            case "$option" in
                --domain) domain=$2 ;;
                --email) email=$2 ;;
                --ssh-allow) ssh_from=$2 ;;
                --user) deploy_user=$2 ;;
                --db-provider) db_provider=$value ;;
                --db-connection|--db-connection-file) db_connection=$value ;;
                --storage) storage=$value ;;
                --s3-bucket) s3_bucket=$value ;;
                --s3-region) s3_region=$value ;;
                --s3-endpoint) s3_endpoint=$value ;;
                --s3-prefix) s3_prefix=$value ;;
                --chunk-storage) chunk_storage=$value ;;
                --s3-access-key|--s3-access-key-file) s3_access=$value ;;
                --s3-secret-key|--s3-secret-key-file) s3_secret=$value ;;
                --admin-password|--admin-password-file) admin_password=$value ;;
                --s3-put-if-none-match) s3_put_if_none_match=$value ;;
                --s3-put-if-match) s3_put_if_match=$value ;;
                --s3-delete-if-match) s3_delete_if_match=$value ;;
            esac
            shift 2 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo 'Run with sudo or as root.' >&2; exit 1; }
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo 'Invalid GitHub repository.' >&2; exit 1; }
prompt() {
    local label=$1 value
    if ! { printf '%s: ' "$label" > /dev/tty && IFS= read -r value < /dev/tty; } 2>/dev/null; then
        echo "Missing $label; provide all options for unattended installation." >&2
        exit 2
    fi
    [[ -n "$value" ]] || { echo "$label cannot be empty." >&2; exit 2; }
    REPLY=$value
}
if [[ -z "$domain" ]]; then prompt 'Domain'; domain=$REPLY; fi
if [[ -z "$email" ]]; then prompt 'Certificate email'; email=$REPLY; fi
if [[ -z "$ssh_from" ]]; then prompt 'SSH allowed IP or CIDR'; ssh_from=$REPLY; fi

export CISTANAS_DOMAIN="$domain" CISTANAS_EMAIL="$email" CISTANAS_SSH_ALLOW_FROM="$ssh_from"
export CISTANAS_DEPLOY_USER="$deploy_user" CISTANAS_GITHUB_REPOSITORY="$repository"
export CISTANAS_DB_PROVIDER="$db_provider" CISTANAS_DB_CONNECTION="$db_connection"
export CISTANAS_STORAGE_PROVIDER="$storage" CISTANAS_S3_BUCKET="$s3_bucket"
export CISTANAS_S3_REGION="$s3_region" CISTANAS_S3_ENDPOINT="$s3_endpoint"
export CISTANAS_S3_PREFIX="$s3_prefix" CISTANAS_CHUNK_STORAGE="$chunk_storage"
export CISTANAS_S3_ACCESS_KEY="$s3_access" CISTANAS_S3_SECRET_KEY="$s3_secret"
export CISTANAS_ADMIN_PASSWORD="$admin_password"
export CISTANAS_S3_PUT_IF_NONE_MATCH="$s3_put_if_none_match" CISTANAS_S3_PUT_IF_MATCH="$s3_put_if_match"
export CISTANAS_S3_DELETE_IF_MATCH="$s3_delete_if_match"
export DEBIAN_FRONTEND=noninteractive
workdir="$(mktemp -d /root/cistanas-setup.XXXXXX)"
trap 'rm -rf -- "$workdir"' EXIT
cd "$workdir"
base="https://github.com/${repository}/releases/latest/download"
curl -fLsS --retry 3 -o cistanas-debian-setup.tar.gz "$base/cistanas-debian-setup.tar.gz"
curl -fLsS --retry 3 -o cistanas-debian-setup.tar.gz.sha256 "$base/cistanas-debian-setup.tar.gz.sha256"
sha256sum -c cistanas-debian-setup.tar.gz.sha256
tar -xzf cistanas-debian-setup.tar.gz
bash ./firstboot.sh
