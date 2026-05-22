#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

workdir=''

cleanup() {
  local status=$?

  if [[ -n "${workdir:-}" && -d "${workdir}" ]]; then
    if ! rm -rf -- "${workdir}"; then
      printf '::warning::Failed to remove temporary workdir\n' >&2
    fi
  fi

  exit "${status}"
}

trap cleanup EXIT

log() {
  printf '[sync] %s\n' "$*"
}

fail() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

warn() {
  printf '::warning::%s\n' "$*" >&2
}

require_cmd() {
  local cmd="$1"

  if ! command -v "${cmd}" >/dev/null 2>&1; then
    fail "Missing required command: ${cmd}"
  fi
}

require_env() {
  local name="$1"
  local value="${!name:-}"

  if [[ -z "${value}" ]]; then
    fail "Missing required environment variable: ${name}"
  fi
}

is_positive_int() {
  local value="$1"

  [[ "${value}" =~ ^[1-9][0-9]*$ ]]
}

is_non_negative_int() {
  local value="$1"

  [[ "${value}" =~ ^[0-9]+$ ]]
}

cf_api() {
  local method="$1"
  local path="$2"
  local payload_file="${3:-}"
  local response=''
  local http_code=''
  local body=''
  local parsed_errors=''
  local response_file="${workdir}/cf-response.json"
  local url="${CF_API_BASE}${path}"

  if [[ -n "${payload_file}" ]]; then
    response="$(curl -sS \
      --request "${method}" \
      --connect-timeout 20 \
      --max-time 180 \
      --retry 3 \
      --retry-delay 2 \
      --retry-all-errors \
      --header "Authorization: Bearer ${CF_API_TOKEN}" \
      --header 'Content-Type: application/json' \
      --data-binary "@${payload_file}" \
      --write-out $'\n%{http_code}' \
      "${url}")" || fail "Cloudflare API request failed: ${method} ${path}"
  else
    response="$(curl -sS \
      --request "${method}" \
      --connect-timeout 20 \
      --max-time 180 \
      --retry 3 \
      --retry-delay 2 \
      --retry-all-errors \
      --header "Authorization: Bearer ${CF_API_TOKEN}" \
      --header 'Content-Type: application/json' \
      --write-out $'\n%{http_code}' \
      "${url}")" || fail "Cloudflare API request failed: ${method} ${path}"
  fi

  http_code="${response##*$'\n'}"
  body="${response%$'\n'*}"
  printf '%s' "${body}" > "${response_file}"

  if [[ ! "${http_code}" =~ ^[0-9]{3}$ ]]; then
    fail "Cloudflare API returned invalid HTTP status for ${method} ${path}"
  fi

  if (( http_code < 200 || http_code >= 300 )); then
    parsed_errors="$(jq -r '[.errors[]? | ((.code // "unknown") | tostring) + ": " + (.message // "unknown error")] | join("; ")' "${response_file}" 2>/dev/null || true)"
    if [[ -n "${parsed_errors}" ]]; then
      fail "Cloudflare API failed: ${method} ${path} HTTP ${http_code}: ${parsed_errors}"
    fi
    fail "Cloudflare API failed: ${method} ${path} HTTP ${http_code}"
  fi

  if ! jq -e '.success == true' "${response_file}" >/dev/null 2>&1; then
    parsed_errors="$(jq -r '[.errors[]? | ((.code // "unknown") | tostring) + ": " + (.message // "unknown error")] | join("; ")' "${response_file}" 2>/dev/null || true)"
    if [[ -n "${parsed_errors}" ]]; then
      fail "Cloudflare API response success=false: ${method} ${path}: ${parsed_errors}"
    fi
    fail "Cloudflare API response success=false: ${method} ${path}"
  fi

  cat "${response_file}"
}

fetch_paginated() {
  local resource_path="$1"
  local output_file="$2"
  local page=1
  local total_pages=1
  local page_file="${workdir}/page.json"
  local result_file="${workdir}/paginated-result.ndjson"

  : > "${result_file}"

  while (( page <= total_pages )); do
    cf_api 'GET' "${resource_path}?per_page=100&page=${page}" > "${page_file}"
    jq -c '.result[]?' "${page_file}" >> "${result_file}"

    total_pages="$(jq -r '.result_info.total_pages // 1' "${page_file}")"
    if ! is_positive_int "${total_pages}"; then
      total_pages=1
    fi

    page=$((page + 1))
  done

  jq -s '{success:true,result:.}' "${result_file}" > "${output_file}"
}

build_list_payload() {
  local list_name="$1"
  local chunk_file="$2"
  local output_file="$3"
  local description="Managed by GitHub Actions. Source: ${BLOCKLIST_URL}"

  jq -Rn \
    --arg name "${list_name}" \
    --arg description "${description}" \
    '{name:$name,description:$description,type:"DOMAIN",items:[inputs | select(length > 0) | {value:.}]}' \
    < "${chunk_file}" > "${output_file}"
}

build_rule_payload() {
  local traffic="$1"
  local output_file="$2"
  local description="Managed by GitHub Actions. Source list prefix: ${LIST_PREFIX}"

  jq -n \
    --arg name "${RULE_NAME}" \
    --arg description "${description}" \
    --arg traffic "${traffic}" \
    --argjson precedence "${RULE_PRECEDENCE}" \
    '{name:$name,description:$description,action:"block",enabled:true,filters:["dns"],traffic:$traffic,precedence:$precedence}' \
    > "${output_file}"
}

normalize_blocklist() {
  local input_file="$1"
  local output_file="$2"

  awk '
    {
      line = $0
      gsub(/\r/, "", line)
      sub(/#.*/, "", line)
      sub(/;.*/, "", line)
      gsub(/^[ \t]+|[ \t]+$/, "", line)
      if (line == "") {
        next
      }

      gsub(/^0\.0\.0\.0[ \t]+/, "", line)
      gsub(/^127\.0\.0\.1[ \t]+/, "", line)
      gsub(/^::1[ \t]+/, "", line)

      if (line ~ /^address=\//) {
        gsub(/^address=\//, "", line)
        sub(/\/.*/, "", line)
      }

      if (line ~ /^\|\|/) {
        gsub(/^\|\|/, "", line)
        sub(/\^.*/, "", line)
      }

      gsub(/^\*\./, "", line)
      gsub(/^https?:\/\//, "", line)
      sub(/\/.*$/, "", line)
      sub(/:.*$/, "", line)
      gsub(/\.$/, "", line)
      line = tolower(line)

      if (line ~ /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/) {
        print line
      }
    }
  ' "${input_file}" | sort -u > "${output_file}"
}

main() {
  require_cmd curl
  require_cmd jq
  require_cmd awk
  require_cmd sort
  require_cmd split
  require_cmd wc
  require_cmd tr
  require_cmd grep
  require_cmd sed
  require_cmd mktemp

  require_env CF_API_TOKEN
  require_env CF_ACCOUNT_ID

  CF_API_BASE="${CF_API_BASE:-https://api.cloudflare.com/client/v4}"
  LIST_PREFIX="${LIST_PREFIX:-Block ads}"
  RULE_NAME="${RULE_NAME:-Block ads}"
  BLOCKLIST_URL="${BLOCKLIST_URL:-https://small.oisd.nl/domainswild2}"
  MAX_LIST_SIZE="${MAX_LIST_SIZE:-1000}"
  MAX_LISTS="${MAX_LISTS:-100}"
  CLOUDFLARE_LIST_LIMIT="${CLOUDFLARE_LIST_LIMIT:-1000}"
  RULE_PRECEDENCE="${RULE_PRECEDENCE:-90}"
  DELETE_EXCESS_LISTS="${DELETE_EXCESS_LISTS:-0}"
  CF_API_SLEEP_SECONDS="${CF_API_SLEEP_SECONDS:-0.15}"

  if [[ ! "${CF_ACCOUNT_ID}" =~ ^[a-fA-F0-9]{32}$ ]]; then
    fail 'CF_ACCOUNT_ID must be a 32-character Cloudflare account ID.'
  fi

  if ! is_positive_int "${MAX_LIST_SIZE}"; then
    fail 'MAX_LIST_SIZE must be a positive integer.'
  fi

  if ! is_positive_int "${MAX_LISTS}"; then
    fail 'MAX_LISTS must be a positive integer.'
  fi

  if ! is_positive_int "${CLOUDFLARE_LIST_LIMIT}"; then
    fail 'CLOUDFLARE_LIST_LIMIT must be a positive integer.'
  fi

  if ! is_non_negative_int "${RULE_PRECEDENCE}"; then
    fail 'RULE_PRECEDENCE must be a non-negative integer.'
  fi

  if [[ "${DELETE_EXCESS_LISTS}" != '0' && "${DELETE_EXCESS_LISTS}" != '1' ]]; then
    fail 'DELETE_EXCESS_LISTS must be 0 or 1.'
  fi

  if (( MAX_LIST_SIZE > CLOUDFLARE_LIST_LIMIT )); then
    fail 'MAX_LIST_SIZE must not be greater than CLOUDFLARE_LIST_LIMIT.'
  fi

  workdir="$(mktemp -d)"
  local raw_file="${workdir}/blocklist.raw"
  local domains_file="${workdir}/domains.txt"
  local chunks_dir="${workdir}/chunks"
  local existing_lists_file="${workdir}/existing-lists.json"
  local existing_rules_file="${workdir}/existing-rules.json"
  local active_ids_file="${workdir}/active-list-ids.txt"
  local required_names_file="${workdir}/required-list-names.txt"
  local domain_count='0'
  local required_lists='0'
  local idx='0'
  local traffic=''
  local rule_id=''
  local rule_payload="${workdir}/rule-payload.json"
  local rule_response="${workdir}/rule-response.json"

  mkdir -p "${chunks_dir}"
  : > "${active_ids_file}"
  : > "${required_names_file}"

  log 'Downloading blocklist'
  curl -fsSL \
    --connect-timeout 20 \
    --max-time 180 \
    --retry 3 \
    --retry-delay 2 \
    --retry-all-errors \
    "${BLOCKLIST_URL}" \
    -o "${raw_file}"

  log 'Normalizing blocklist'
  normalize_blocklist "${raw_file}" "${domains_file}"

  domain_count="$(wc -l < "${domains_file}" | tr -d '[:space:]')"
  if [[ -z "${domain_count}" ]]; then
    domain_count='0'
  fi

  if (( domain_count < 1 )); then
    fail 'Normalized blocklist is empty.'
  fi

  required_lists=$(( (domain_count + MAX_LIST_SIZE - 1) / MAX_LIST_SIZE ))

  if (( required_lists > MAX_LISTS )); then
    fail "Required Cloudflare lists (${required_lists}) exceed MAX_LISTS (${MAX_LISTS}). Increase MAX_LISTS or reduce MAX_LIST_SIZE/source list."
  fi

  log "Domains: ${domain_count}"
  log "Required Cloudflare lists: ${required_lists}"

  split -l "${MAX_LIST_SIZE}" -d -a 3 "${domains_file}" "${chunks_dir}/chunk-"

  log 'Fetching existing Cloudflare Gateway lists'
  fetch_paginated "/accounts/${CF_ACCOUNT_ID}/gateway/lists" "${existing_lists_file}"

  idx=0
  while IFS= read -r chunk_file; do
    idx=$((idx + 1))

    local list_name=''
    local list_id=''
    local payload_file=''
    local list_response=''

    list_name="$(printf '%s - %03d' "${LIST_PREFIX}" "${idx}")"
    payload_file="${workdir}/list-${idx}.json"
    printf '%s\n' "${list_name}" >> "${required_names_file}"

    build_list_payload "${list_name}" "${chunk_file}" "${payload_file}"

    list_id="$(jq -r --arg name "${list_name}" 'first(.result[]? | select(.name == $name) | .id) // empty' "${existing_lists_file}")"

    if [[ -n "${list_id}" ]]; then
      log "Updating list: ${list_name}"
      list_response="$(cf_api 'PUT' "/accounts/${CF_ACCOUNT_ID}/gateway/lists/${list_id}" "${payload_file}")"
      printf '%s' "${list_response}" > "${workdir}/list-${idx}-response.json"
    else
      log "Creating list: ${list_name}"
      list_response="$(cf_api 'POST' "/accounts/${CF_ACCOUNT_ID}/gateway/lists" "${payload_file}")"
      printf '%s' "${list_response}" > "${workdir}/list-${idx}-response.json"
      list_id="$(jq -r '.result.id // empty' "${workdir}/list-${idx}-response.json")"
    fi

    if [[ -z "${list_id}" ]]; then
      fail "Unable to resolve Cloudflare list ID for ${list_name}."
    fi

    printf '%s\n' "${list_id}" >> "${active_ids_file}"
    sleep "${CF_API_SLEEP_SECONDS}"
  done < <(find "${chunks_dir}" -type f -name 'chunk-*' | sort)

  traffic="$(jq -R -s -r 'split("\n") | map(select(length > 0)) | map("dns.fqdn in $" + .) | join(" or ")' "${active_ids_file}")"

  if [[ -z "${traffic}" ]]; then
    fail 'Generated Gateway rule traffic expression is empty.'
  fi

  log 'Fetching existing Cloudflare Gateway rules'
  fetch_paginated "/accounts/${CF_ACCOUNT_ID}/gateway/rules" "${existing_rules_file}"

  rule_id="$(jq -r --arg name "${RULE_NAME}" 'first(.result[]? | select(.name == $name and ((.filters // []) | index("dns"))) | .id) // empty' "${existing_rules_file}")"

  build_rule_payload "${traffic}" "${rule_payload}"

  if [[ -n "${rule_id}" ]]; then
    log "Updating DNS Gateway rule: ${RULE_NAME}"
    cf_api 'PUT' "/accounts/${CF_ACCOUNT_ID}/gateway/rules/${rule_id}" "${rule_payload}" > "${rule_response}"
  else
    log "Creating DNS Gateway rule: ${RULE_NAME}"
    cf_api 'POST' "/accounts/${CF_ACCOUNT_ID}/gateway/rules" "${rule_payload}" > "${rule_response}"
  fi

  if [[ "${DELETE_EXCESS_LISTS}" == '1' ]]; then
    log 'Deleting excess Cloudflare Gateway lists'

    while IFS=$'\t' read -r list_id list_name; do
      if [[ -z "${list_id}" || -z "${list_name}" ]]; then
        continue
      fi

      if grep -Fxq -- "${list_name}" "${required_names_file}"; then
        continue
      fi

      log "Deleting excess list: ${list_name}"
      cf_api 'DELETE' "/accounts/${CF_ACCOUNT_ID}/gateway/lists/${list_id}" > /dev/null
      sleep "${CF_API_SLEEP_SECONDS}"
    done < <(jq -r --arg prefix "${LIST_PREFIX} - " '.result[]? | select(.name | startswith($prefix)) | [.id, .name] | @tsv' "${existing_lists_file}")
  else
    warn 'DELETE_EXCESS_LISTS is disabled; old managed lists will be kept.'
  fi

  log 'Done'
}

main "$@"
