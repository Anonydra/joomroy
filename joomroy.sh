#!/bin/bash

# === Colors ===
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[0;36m'
NC='\033[0m'  # No Color

# === Print symbols with color ===
print_symbol() {
  case "$1" in
    +) printf "[${GREEN}+${NC}] " ;;
    -) printf "[${RED}-${NC}] " ;;
    \!) printf "[${YELLOW}!${NC}] " ;;
    \*) printf "[*] " ;;
    *)  printf "[%s] " "$1" ;;
  esac
}

# === Reset counters ===
reset_counters() {
  vulnerable_version_found=0
  vulnerable_components_count=0
  sensitive_files_count=0
  backup_files_count=0
  admin_accessible=0
  version_missing=0
}

# === Extract root URL (scheme + hostname) ===
get_root_url() {
  local url="$1"
  echo "$url" | sed -E 's#^(https?://[^/]+).*#\1#'
}

# === Print finished time ===
print_finished_time() {
  local now
  now=$(date '+%Y-%m-%d %H:%M:%S')
  echo -e "[${GREEN}+${NC}] Finished at: $now"
  echo
}

# === Help Menu ===
usage() {
  echo -e "\nUsage: $0 [OPTIONS]\n"
  echo "Options:"
  echo "  -u <url>     Scan a single Joomla site at the specified URL."
  echo "  -f <file>    Scan multiple Joomla sites listed line-by-line in the specified file."
  echo "  -d <dork>    Use a Google Dork (via DuckDuckGo) to find Joomla sites."
  echo "  -h           Display this help message and exit."
  echo
  echo "Examples:"
  echo "  $0 -u 'https://example.com'"
  echo "  $0 -f targets.txt"
  echo "  $0 -d 'inurl:/administrator/ intitle:\"Joomla\"'"
  echo
}

# === DuckDuckGo Dork Search ===
search_dork() {
  local dork="$1"
  local results_file="$2"

  echo -e "[${BLUE}*${NC}] Searching for: \"$dork\" via DuckDuckGo..."
  ddg_url="https://html.duckduckgo.com/html/?q=$(echo "$dork" | sed 's/ /+/g')"

  curl -s -A "Mozilla/5.0" "$ddg_url" | \
    grep -oP '(?<=href=")(https?://[^"]+)' | \
    sed -E 's/(#.*|\?.*)$//' | \
    sort -u | tee "$results_file" > /dev/null

  found=$(wc -l < "$results_file")
  echo -e "[${GREEN}+${NC}] Found $found unique URLs"
}

# === Parse CLI Args ===
while getopts ":u:f:d:h" opt; do
  case "$opt" in
    u) DOMAIN="$OPTARG" ;;
    f) FILE="$OPTARG" ;;
    d) DORK="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

[[ -z "$DOMAIN" && -z "$FILE" && -z "$DORK" ]] && usage && exit 1

# === Load libs ===
source "$(dirname "$0")/lib/utils.sh"
source "$(dirname "$0")/lib/output.sh"
source "$(dirname "$0")/config/data.sh"
source "$(dirname "$0")/lib/detectors.sh"
source "$(dirname "$0")/lib/checks.sh"

# === Show banner ===
clear
[[ -f banner.txt ]] && echo -e "${RED}$(cat banner.txt)${NC}"
echo
echo -e "[${RED}*${NC}] Author : ${CYAN}Anonydra${NC}"
echo -e "[${RED}*${NC}] Version: ${CYAN}0.1${NC}"
echo -e "[${RED}*${NC}] Time   : ${CYAN}$(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo "================================"
echo

# === Main Scan Logic ===
run_scan() {
  local url="$1"
  reset_counters

  echo -e "[${BLUE}*${NC}] Scanning $(get_root_url "$url")..."
  echo

  check_waf "$url"
  check_version "$url" || version_missing=1
  check_headers_version "$url"

  [[ $version_missing -eq 1 && $has_waf -eq 1 ]] && print_symbol "!" && echo "WAF may be blocking version info."

  check_admin "$url"
  check_meta "$url"
  check_endpoint "$url"
  check_backup "$url"
  check_sensitive_files "$url"
  check_vuln_components "$url"
  check_user_enum "$url"
  check_registration_login_pages "$url"
  check_debug_files "$url"
  check_env_files "$url"

  print_finished_time
}

# === Entry Point ===
if [[ -n "$FILE" ]]; then
  [[ ! -f "$FILE" ]] && echo -e "${RED}[!] File not found: $FILE${NC}" && exit 1
  count=$(grep -cvE '^\s*$' "$FILE")
  echo -e "[${BLUE}*${NC}] Loaded $count targets"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    run_scan "$line"
  done < "$FILE"

elif [[ -n "$DORK" ]]; then
  TMP_FILE=$(mktemp)
  search_dork "$DORK" "$TMP_FILE"
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    run_scan "$url"
  done < "$TMP_FILE"
  rm "$TMP_FILE"

elif [[ -n "$DOMAIN" ]]; then
  run_scan "$DOMAIN"
fi
