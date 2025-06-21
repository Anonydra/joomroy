#!/bin/bash

# === Colors ===
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color

# Source the data with CVE info (adjust path if needed)
source ./config/data.sh

print_symbol() {
  case "$1" in
    +) printf "[${GREEN}+${NC}] " ;;
    -) printf "[${RED}-${NC}] " ;;
    \!) printf "[${YELLOW}!${NC}] " ;;
    \*) printf "[*] " ;;
    *)  printf "[%s] " "$1" ;;
  esac
}

get_root_url() {
  local url="$1"
  echo "$url" | sed -E 's#^(https?://[^/]+).*#\1#'
}

print_finished_time() {
  local now
  now=$(date '+%Y-%m-%d %H:%M:%S')
  echo
  echo -e "[${GREEN}+${NC}] Finished at: $now"
  echo
}
