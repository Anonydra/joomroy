is_joomla() {
  local url="$1"
  curl -sk -o /dev/null --max-time 3 "${url%/}/administrator/manifests/files/joomla.xml" | grep -q "200" && return 0
  curl -sk --max-time 3 "$url" | grep -iq 'meta name="generator" content="Joomla' && return 0
  return 1
}

check_version() {
  for p in "${PATHS[@]}"; do
    v=$(curl -sk --max-time 5 "${1%/}$p" | grep -oPm1 "(?<=<version>)[^<]+")
    if [[ -n $v ]]; then
      [[ -n ${VULN_CVES[$v]} ]] && print_symbol "-" && echo "Joomla v${v} vulnerable - ${VULN_CVES[$v]}" && vulnerable_version_found=1
      return 0
    fi
  done
  return 1
}

check_headers_version() {
  curl -sk -I --max-time 3 "$1" | grep -i 'X-Generator' &>/dev/null && echo "Header Joomla version found"
}

check_waf() {
  wafwoof -u "$1" 2>/dev/null | grep -q "WAF detected"
}
