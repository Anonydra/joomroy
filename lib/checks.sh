#!/bin/bash

# === Ensure CURL_TIMEOUT is a valid number, else default to 5 ===
if ! [[ "$CURL_TIMEOUT" =~ ^[0-9]+$ ]]; then
  CURL_TIMEOUT=5
fi

# === Colors ===
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'  # No Color


# === Check for Admin Page (Admin Exists) ===
check_admin() {
  local url="$1"
  local base_url
  local timeout="${CURL_TIMEOUT:-5}"

  # Extract root URL (scheme + host)
  base_url=$(echo "$url" | sed -E 's#^(https?://[^/]+).*#\1#')

  local admin_url="${base_url}/administrator/"
  status_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time "$timeout" "$admin_url")

  if [[ "$status_code" == "200" ]]; then
    print_symbol "+"
    echo "Admin exists (HTTP 200): $admin_url"
    admin_accessible=1
    return 0
  else
    print_symbol "-"
    echo "Admin does not exist or inaccessible (HTTP $status_code): $admin_url"
    return 1
  fi
}

# === Version Detection ===
check_version() {
  local url="$1"
  local base_url
  local version=""
  local timeout="${CURL_TIMEOUT:-5}"
  local paths=(
    "/language/en-GB/en-GB.xml"
    "/administrator/manifests/files/joomla.xml"
  )

  # Extract root URL (scheme + host) only
  base_url=$(echo "$url" | sed -E 's#^(https?://[^/]+).*#\1#')

  for path in "${paths[@]}"; do
    full_url="${base_url}${path}"
    xml=$(curl -sk --max-time "$timeout" "$full_url")
    version=$(echo "$xml" | grep -oPm1 "(?<=<version>)[^<]+")
    if [[ -n "$version" ]]; then
      print_symbol "+"
      echo -e "Joomla version ${GREEN}$version${NC} detected at: $full_url"

      detected_joomla_version="$version"

      if [[ " ${VULN_VERSIONS[*]} " == *" $version "* ]]; then
        print_symbol "!"
        echo -e "Version ${GREEN}$version${NC} has known vulnerabilities."

        if [[ -v VULN_CVES["$version"] ]]; then
          cve_for_version="${VULN_CVES[$version]}"
          echo -e "[${YELLOW}!${NC}] Associated CVE(s): ${RED}$cve_for_version${NC}"
        fi
      fi
      return 0
    fi
  done

  homepage_html=$(curl -sk --max-time "$timeout" "$base_url/")
  version=$(echo "$homepage_html" | sed -nE 's/.*<meta[[:space:]]+name=["'\'']generator["'\''][[:space:]]+content=["'\'']Joomla[[:space:]]*([0-9\.]+).*/\1/ip' | head -n1)

  if [[ -n "$version" ]]; then
    print_symbol "+"
    echo "Joomla version $version detected from homepage"

    detected_joomla_version="$version"

    if [[ " ${VULN_VERSIONS[*]} " == *" $version "* ]]; then
      print_symbol "!"
      echo "Version $version has known vulnerabilities."

      if [[ -v VULN_CVES["$version"] ]]; then
        cve_for_version="${VULN_CVES[$version]}"
        echo -e "[${YELLOW}!${NC}] CVE(s): ${RED}$cve_for_version${NC}"
      fi
    fi
    return 0
  fi

  print_symbol "-"
  echo "Could not detect Joomla version"
  return 1
}

# === Meta Generator Tag Check ===
check_meta() {
  local url="$1"
  html=$(curl -sk --max-time "$CURL_TIMEOUT" "$url")

  # Extract the Joomla meta generator tag line (case-insensitive)
  local match
  match=$(echo "$html" | grep -i 'meta name="generator" content="Joomla' | tr -d '\n' | sed 's/[[:space:]]\+/ /g')

  if [[ -n "$match" ]]; then
    print_symbol "+"
    echo "Joomla generator tag found at:$match"
  else
    print_symbol "-"
    echo "Joomla generator tag not found"
  fi
}

# === Endpoint Checks ===
check_endpoint() {
  local input_url="$1"
  # Extract root URL: scheme + host (remove trailing slash if any)
  local base_url=$(echo "$input_url" | sed -E 's#^(https?://[^/]+).*#\1#')

  for u in "${ENDPOINTS[@]}"; do
    # Append endpoint ensuring exactly one slash between base and endpoint
    url="${base_url%/}${u}"
    s=$(curl -sk -o /dev/null -w "%{http_code}" --max-time "${CURL_TIMEOUT:-5}" "$url")
    if [[ $s == 200 ]]; then
      print_symbol "+"
      echo "Endpoint accessible: $url"
    fi
  done
}

# === Backup File Checks ===
check_backup() {
  for u in "${BACKUPS[@]}"; do
    url="${1%/}$u"
    s=$(curl -sk -o /dev/null -w "%{http_code}" --max-time "$CURL_TIMEOUT" "$url")
    if [[ $s == 200 ]]; then
      print_symbol "+"
      echo "Backup accessible: ${url}"
      ((backup_files_count++))
    fi
  done
}

# === Sensitive Files Checks ===
check_sensitive_files() {
  for f in "${SENSITIVE_FILES[@]}"; do
    url="${1%/}$f"
    s=$(curl -sk -o /dev/null -w "%{http_code}" --max-time "$CURL_TIMEOUT" "$url")
    if [[ $s == 200 ]]; then
      print_symbol "+"
      echo "Sensitive file accessible: ${url}"
      ((sensitive_files_count++))
    fi
  done
}

# === Vulnerable Components Check ===
check_vuln_components() {
  for c in "${VULN_COMPONENTS[@]}"; do
    url="${1%/}$c"
    s=$(curl -sk -o /dev/null -w "%{http_code}" --max-time "$CURL_TIMEOUT" "$url")
    if [[ $s == 200 ]]; then
      print_symbol "+"
      echo "Vulnerable component detected: ${url}"
      ((vulnerable_components_count++))
    fi
  done
}

# === User Enumeration Check ===
check_user_enum() {
  base_url="${1%/}"
  for id in {1..3}; do
    url="$base_url/index.php?option=com_users&view=profile&id=$id"
    s=$(curl -sk -o /dev/null -w "%{http_code}" --max-time "$CURL_TIMEOUT" "$url")
    if [[ $s == 200 ]]; then
      print_symbol "!"
      echo "Possible user enumeration at: $url"
    fi
  done
}

# === Registration & Login Page Check ===
check_registration_login_pages() {
  # Extract root URL (scheme + host only)
  local base_root
  base_root=$(get_root_url "$1")

  for page in "index.php?option=com_users&view=login" "index.php?option=com_users&view=registration"; do
    local url="${base_root%/}/$page"
    local status_code
    status_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time "${CURL_TIMEOUT:-5}" "$url")
    if [[ $status_code == 200 ]]; then
      print_symbol "+"
      echo "Joomla page accessible: $url"
    else
      print_symbol "-"
      echo "Joomla page not accessible: $url"
    fi
  done
}

# === Security Headers Check ===
check_security_headers() {
  local url="${1%/}"
  echo -e "[${BLUE}*${NC}] Checking security headers for $url"

  local headers
  headers=$(curl -skI --max-time "${CURL_TIMEOUT:-5}" "$url")

  local required_headers=(
    "Content-Security-Policy"
    "X-Frame-Options"
    "Strict-Transport-Security"
    "X-XSS-Protection"
    "Referrer-Policy"
  )

  for header in "${required_headers[@]}"; do
    if echo "$headers" | grep -iq "^$header:"; then
      print_symbol "+"
      echo "$header found"
    else
      print_symbol "!"
      echo "$header missing"
    fi
  done
}

# === Main Scan Logic ===
run_scan() {
  local url="$1"
  reset_counters

  echo -e "[${BLUE}*${NC}] Scanning $(get_root_url "$url")..."
  echo " |"

  local has_waf=0
  local version_missing=0

  check_waf "$url" && has_waf=1

  if ! is_joomla "$url"; then
    print_symbol "-" && echo "Not a Joomla site."
    return
  fi

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
  
  # <-- Added call to new security headers check here -->
  check_security_headers "$url"
  print_finished_time
}

check_debug_files() {
  local base_url="${1%/}"
  local debug_files=(
    "/phpinfo.php"
    "/tmp/phpinfo.php"
    "/logs/error_log"
    "/logs/access_log"
    "/administrator/error_log"
    "/administrator/logs/error_log"
  )

  for f in "${debug_files[@]}"; do
    url="$base_url$f"
    status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time "$CURL_TIMEOUT" "$url")
    if [[ "$status" == "200" ]]; then
      print_symbol "!"
      echo "Debug/info file accessible: $url"
    fi
  done
}

check_env_files() {
  local base_url="${1%/}"
  local env_files=(
    "/.env"
    "/configuration.php"
    "/configuration.php.bak"
    "/configuration.php~"
  )

  for f in "${env_files[@]}"; do
    url="$base_url$f"
    status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time "$CURL_TIMEOUT" "$url")
    if [[ "$status" == "200" ]]; then
      print_symbol "!"
      echo "Sensitive config file accessible: $url"
    fi
  done
}

# === WAF Detection ===
check_waf() {
  local url="$1"
  local timeout="${CURL_TIMEOUT:-5}"
  local headers
  headers=$(curl -skI --max-time "$timeout" "$url" | tr -d '\r')

  # Known WAF-related headers or indicative values
  local waf_indicators=(
    "x-sucuri" "x-fireeye" "x-paloalto" "x-ddos"
    "x-cdn" "x-mod-security" "cf-ray" "x-cf" "x-waf" "x-sucuri-id"
    "x-imunify" "akamai" "incapsula" "x-envoy" "x-waf-firewall"
  )

  while IFS= read -r line; do
    header_name=$(echo "$line" | cut -d':' -f1 | tr '[:upper:]' '[:lower:]')
    for indicator in "${waf_indicators[@]}"; do
      if [[ "$header_name" == "$indicator"* ]]; then
        echo -e "[${YELLOW}!${NC}] WAF detected (based on headers): $line"
        return
      fi
    done
  done <<< "$headers"
}
