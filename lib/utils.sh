timestamp() { date +"%Y-%m-%d %H:%M:%S"; }

get_root_url() {
  local url="$1"
  echo "$url" | sed -E 's#^(https?://[^/]+).*#\1#'
}
