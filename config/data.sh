#!/bin/bash

# === Joomla Manifest Paths for Version Detection ===
PATHS=(
  "/administrator/manifests/files/joomla.xml"
  "/language/en-GB/en-GB.xml"
  "/language/en-GB/en-GB.localise.xml"
  "/administrator/language/en-GB/en-GB.xml"
)

# === Common Joomla Public and Sensitive Endpoints ===
ENDPOINTS=(
  "/robots.txt"
  "/sitemap.xml"
  "/xmlrpc.php"
  "/index.php"
  "/administrator/"
  "/templates/"
  "/modules/"
  "/plugins/"
  "/media/"
  "/cache/"
  "/components/"
  "/language/"
  "/libraries/"
  "/includes/"
  "/tmp/"
  "/logs/"
)

# === Common Backup File Names to Test for Leaks ===
BACKUPS=(
  "/configuration.php.bak"
  "/configuration.php~"
  "/configuration.old.php"
  "/README.txt"
  "/readme.html"
  "/license.txt"
  "/.git/config"
  "/.svn/entries"
  "/configuration.php.save"
  "/configuration.php.old"
  "/backup.zip"
  "/backup.tar.gz"
  "/site-backup.tar.gz"
  "/site-backup.zip"
  "/joomla-backup.zip"
  "/joomla-backup.tar.gz"
)

# === Sensitive Files Often Exposed ===
SENSITIVE_FILES=(
  "/configuration.php"
  "/.env"
  "/.htaccess"
  "/.htpasswd"
  "/phpinfo.php"
  "/tmp/phpinfo.php"
  "/logs/error_log"
  "/logs/access_log"
  "/administrator/error_log"
  "/administrator/logs/error_log"
  "/web.config"
  "/composer.json"
  "/composer.lock"
)

# === Known Vulnerable Components/Paths ===
VULN_COMPONENTS=(
  "/components/com_jce/"
  "/components/com_fabrik/"
  "/components/com_cck/"
  "/components/com_contenthistory/"
  "/components/com_akeeba/"
  "/components/com_foxcontact/"
  "/components/com_banners/"
  "/components/com_hikashop/"
  "/components/com_sourcerer/"
  "/components/com_revslider/"
  "/components/com_rsform/"
  "/components/com_virtuemart/"
  "/components/com_k2/"
  "/components/com_jdownloads/"
  "/components/com_civicrm/"
  "/components/com_joomblog/"
  "/components/com_mijoshop/"
  "/components/com_jcomments/"
  "/components/com_easysocial/"
  "/components/com_adsmanager/"
  "/components/com_weblinks/"
  "/components/com_flexicontent/"
  "/components/com_finder/"
)

# === Common Admin Usernames to Bruteforce ===
DEFAULT_ADMIN_USERNAMES=(
  "admin"
  "administrator"
  "root"
  "test"
  "joomla"
  "demo"
)

# === Vulnerable Joomla Versions ===
VULN_VERSIONS=(
  "1.5.0" "1.5.1" "1.5.2" "1.5.3" "1.5.4" "1.5.5" "1.5.6" "1.5.7" "1.5.8" "1.5.9" "1.5.15"
  "2.5.0" "2.5.1" "2.5.2" "2.5.3" "2.5.4" "2.5.5" "2.5.6" "2.5.7" "2.5.8" "2.5.9" "2.5.10"
  "3.0.0" "3.0.1" "3.0.2" "3.0.3" "3.1.0" "3.2.0" "3.3.0"
  "3.4.0" "3.4.1" "3.4.2" "3.4.3" "3.4.4" "3.4.5" "3.4.6" "3.4.7" "3.4.8"
  "3.5.0" "3.5.1" "3.5.2" "3.6.0" "3.6.1" "3.6.5" "3.7.0" "3.7.1" "3.10.6"
)

# === Known CVEs by Version (Map) ===
declare -A VULN_CVES=(
  ["1.5.0"]="CVE-2012-1598"
  ["1.5.15"]="CVE-2015-8562, CVE-2010-1435, CVE-2010-1433, CVE-2017-7983, CVE-2010-1649"
  
  ["2.5.0"]="CVE-2020-35612, CVE-2020-35611, CVE-2018-12712"
  ["2.5.5"]="CVE-2012-2747, CVE-2012-2748"
  ["2.5.8"]="CVE-2013-5576"

  ["3.0.0"]="CVE-2015-5608, CVE-2020-35613, CVE-2021-26028"
  
  ["3.2.0"]="CVE-2014-7228, CVE-2017-7987"
  
  # 3.4.0 to 3.4.8 all share CVE-2015-8562
  ["3.4.0"]="CVE-2015-8562"
  ["3.4.1"]="CVE-2015-8562"
  ["3.4.2"]="CVE-2015-8562"
  ["3.4.3"]="CVE-2015-8562"
  ["3.4.4"]="CVE-2015-8562"
  ["3.4.5"]="CVE-2015-8562"
  ["3.4.6"]="CVE-2015-8562"
  ["3.4.7"]="CVE-2015-8562"
  ["3.4.8"]="CVE-2015-8562"
  
  ["3.5.0"]="CVE-2016-8870"
  ["3.6.5"]="CVE-2016-9838"
  ["3.7.0"]="CVE-2017-7983, CVE-2017-7984, CVE-2017-7985, CVE-2017-7986, CVE-2017-7987, CVE-2017-7988, CVE-2017-7989, CVE-2017-8057"
  ["3.10.6"]="CVE-2022-23796"
)
