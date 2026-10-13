#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "cistanas-update must run as root." >&2
    exit 1
fi

readonly INSTALL_ROOT="/opt/cistanas"
readonly RELEASE_ROOT="${INSTALL_ROOT}/releases"
readonly CURRENT_LINK="${INSTALL_ROOT}/current"
readonly UPDATE_ENV="/etc/cistanas/update.env"
readonly STATUS_FILE="/var/lib/cistanas/update-status.json"
readonly CHECK_REQUEST_FILE="/var/lib/cistanas/update-check-request.json"
readonly REQUEST_FILE="/var/lib/cistanas/update-request.json"
readonly LOCK_FILE="/var/lib/cistanas/update.lock"
readonly SERVICE_NAME="cistanas"
readonly HEALTH_URL="http://127.0.0.1:8080/health"

if [[ ! -r "${UPDATE_ENV}" ]]; then
    echo "Update configuration is missing: ${UPDATE_ENV}" >&2
    exit 1
fi
# This file is root-owned and mode 0600; it may contain a GitHub read token.
# shellcheck disable=SC1091
source "${UPDATE_ENV}"

readonly repository="${CISTANAS_GITHUB_REPOSITORY:?CISTANAS_GITHUB_REPOSITORY is required}"
if [[ ! "${repository}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    echo "Invalid GitHub repository: ${repository}" >&2
    exit 1
fi

case "$(uname -m)" in
    x86_64) readonly runtime="linux-x64" ;;
    aarch64|arm64) readonly runtime="linux-arm64" ;;
    *)
        echo "Unsupported Debian architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

curl_args=(--fail --silent --show-error --location --retry 3
    -H 'Accept: application/vnd.github+json'
    -H 'X-GitHub-Api-Version: 2022-11-28')
if [[ -n "${CISTANAS_GITHUB_TOKEN:-}" ]]; then
    curl_args+=(--header "Authorization: Bearer ${CISTANAS_GITHUB_TOKEN}")
fi

write_status() {
    local state="$1"
    local current_version="$2"
    local latest_version="$3"
    local update_available="$4"
    local message="$5"
    local requested_version="${6:-}"
    local checked_at
    local tmp_file

    checked_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    tmp_file="$(mktemp "${STATUS_FILE}.XXXXXX")"
    jq -n \
        --arg state "${state}" \
        --arg current "${current_version}" \
        --arg latest "${latest_version}" \
        --arg message "${message}" \
        --arg requested "${requested_version}" \
        --arg checked "${checked_at}" \
        --argjson available "${update_available}" \
        '{state:$state,
          currentVersion:(if $current == "" then null else $current end),
          latestVersion:(if $latest == "" then null else $latest end),
          updateAvailable:$available,
          requestedVersion:(if $requested == "" then null else $requested end),
          checkedAt:$checked,
          message:(if $message == "" then null else $message end)}' \
        > "${tmp_file}"
    chown root:cistanas "${tmp_file}"
    chmod 0640 "${tmp_file}"
    mv -f "${tmp_file}" "${STATUS_FILE}"
}

current_version=""
if [[ -L "${CURRENT_LINK}" ]]; then
    current_version="$(basename "$(readlink -f "${CURRENT_LINK}")")"
fi

release_json=""
latest_version=""
asset_name=""
checksum_name=""
asset_url=""
checksum_url=""

fetch_release() {
    local requested_version="${1:-}"
    local release_url="https://api.github.com/repos/${repository}/releases/latest"
    if [[ -n "${requested_version}" ]]; then
        release_url="https://api.github.com/repos/${repository}/releases/tags/${requested_version}"
    fi

    release_json="$(curl "${curl_args[@]}" "${release_url}")"
    latest_version="$(jq -er '.tag_name | select(test("^v[0-9]+\\.[0-9]+\\.[0-9]+$"))' <<<"${release_json}")"
    asset_name="cistanas-${latest_version}-${runtime}.tar.gz"
    checksum_name="${asset_name}.sha256"
    asset_url="$(jq -er --arg name "${asset_name}" '.assets[] | select(.name == $name) | .browser_download_url' <<<"${release_json}")"
    checksum_url="$(jq -er --arg name "${checksum_name}" '.assets[] | select(.name == $name) | .browser_download_url' <<<"${release_json}")"
}

check_release() {
    if ! fetch_release; then
        write_status "check_failed" "${current_version}" "" false "GitHub Releaseの確認に失敗しました。"
        return 1
    fi

    if [[ "${current_version}" == "${latest_version}" ]]; then
        write_status "up_to_date" "${current_version}" "${latest_version}" false "最新バージョンです。"
        echo "CistaNAS is already up to date: ${latest_version}"
    else
        write_status "update_available" "${current_version}" "${latest_version}" true "更新を適用できます。"
        echo "CistaNAS update is available: ${current_version:-none} -> ${latest_version}"
    fi
}

apply_release() {
    local requested_version=""
    if [[ -s "${REQUEST_FILE}" ]]; then
        requested_version="$(jq -er '.version | select(test("^v[0-9]+\\.[0-9]+\\.[0-9]+$"))' "${REQUEST_FILE}")" || {
            rm -f "${REQUEST_FILE}"
            write_status "apply_failed" "${current_version}" "" false "更新要求のバージョンが不正です。"
            return 1
        }
        rm -f "${REQUEST_FILE}"
    fi

    write_status "checking" "${current_version}" "" false "更新対象を確認しています。" "${requested_version}"
    if ! fetch_release "${requested_version}"; then
        write_status "apply_failed" "${current_version}" "" false "指定されたGitHub Releaseの取得に失敗しました。" "${requested_version}"
        return 1
    fi

    if [[ "${current_version}" == "${latest_version}" ]]; then
        write_status "up_to_date" "${current_version}" "${latest_version}" false "最新バージョンです。"
        return 0
    fi

    write_status "downloading" "${current_version}" "${latest_version}" true "配布物をダウンロードしています。" "${requested_version}"
    work_dir="$(mktemp -d /tmp/cistanas-update.XXXXXX)"
    stage_dir="${RELEASE_ROOT}/.${latest_version}.staging.$$"
    cleanup() {
        rm -rf "${work_dir}" "${stage_dir}"
    }
    trap cleanup EXIT

    archive_path="${work_dir}/${asset_name}"
    checksum_path="${work_dir}/${checksum_name}"
    curl "${curl_args[@]}" "${asset_url}" --output "${archive_path}"
    curl "${curl_args[@]}" "${checksum_url}" --output "${checksum_path}"
    (
        cd "${work_dir}"
        sha256sum --check --status "${checksum_name}"
    ) || {
        write_status "apply_failed" "${current_version}" "${latest_version}" false "SHA-256検証に失敗しました。" "${requested_version}"
        return 1
    }

    write_status "installing" "${current_version}" "${latest_version}" true "配布物を展開しています。" "${requested_version}"
    install -d -o root -g root -m 0755 "${stage_dir}"
    tar --extract --gzip --file "${archive_path}" --directory "${stage_dir}"
    if [[ ! -x "${stage_dir}/CistaNAS.Web" ]]; then
        write_status "apply_failed" "${current_version}" "${latest_version}" false "配布物にCistaNAS.Webがありません。" "${requested_version}"
        return 1
    fi
    chown -R root:root "${stage_dir}"
    find "${stage_dir}" -type d -exec chmod 0755 {} +
    chmod 0755 "${stage_dir}/CistaNAS.Web"
    mv "${stage_dir}" "${RELEASE_ROOT}/${latest_version}"

    previous_target=""
    if [[ -L "${CURRENT_LINK}" ]]; then
        previous_target="$(readlink -f "${CURRENT_LINK}")"
    fi
    write_status "restarting" "${current_version}" "${latest_version}" true "サービスを再起動しています。" "${requested_version}"
    ln -sfnT "${RELEASE_ROOT}/${latest_version}" "${CURRENT_LINK}"
    systemctl restart "${SERVICE_NAME}"

    healthy=false
    for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
        if curl --fail --silent --max-time 5 "${HEALTH_URL}" >/dev/null; then
            healthy=true
            break
        fi
        sleep 1
    done

    if [[ "${healthy}" != true ]]; then
        echo "The new release failed its health check: ${latest_version}" >&2
        if [[ -n "${previous_target}" && -d "${previous_target}" ]]; then
            ln -sfnT "${previous_target}" "${CURRENT_LINK}"
            systemctl restart "${SERVICE_NAME}" || true
        fi
        write_status "apply_failed" "${current_version}" "${latest_version}" false "ヘルスチェックに失敗したため、直前の配布物へ戻しました。" "${requested_version}"
        return 1
    fi

    # Keep the current release and the two previous releases for rollback.
    mapfile -t old_releases < <(find "${RELEASE_ROOT}" -mindepth 1 -maxdepth 1 -type d -name 'v[0-9]*' -printf '%f\n' | sort -V -r)
    for old_release in "${old_releases[@]:3}"; do
        rm -rf "${RELEASE_ROOT:?}/${old_release}"
    done
    write_status "updated" "${latest_version}" "${latest_version}" false "更新が完了しました。" "${requested_version}"
    echo "CistaNAS updated successfully: ${latest_version}"
}

mkdir -p "$(dirname "${STATUS_FILE}")"
exec 9>"${LOCK_FILE}"
flock 9

case "${1:-apply}" in
    check)
        rm -f "${CHECK_REQUEST_FILE}"
        check_release
        ;;
    apply) apply_release ;;
    *)
        echo "Usage: cistanas-update {check|apply}" >&2
        exit 2
        ;;
esac
