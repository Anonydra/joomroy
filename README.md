Joomroy

Joomroy is a Bash-based tool for scanning Joomla websites for version info, vulnerabilities (based on known CVEs), sensitive files, admin panel exposure, and potential WAF detection.
🛠 Installation

git clone https://github.com/Anonydra/joomroy.git
cd joomroy
chmod +x joomroy.sh

📌 Usage

Run the tool with:

./joomroy.sh -h

Available Options:

    -u <url>  Scan a single Joomla site

    -f <file>  Scan multiple sites listed line-by-line in a file

    -d <dork>  Use a DuckDuckGo dork to find Joomla targets

    -h     Show help menu

✅ Examples

Scan a single site: ./joomroy.sh -u https://example.com

Scan multiple targets from a file: ./joomroy.sh -f targets.txt

Search for Joomla sites using a dork: ./joomroy.sh -d 'inurl:/administrator/ intitle:"Joomla"'

💡 Features

    Detects Joomla version and matches against known CVEs

    Finds accessible admin panels, login/registration pages

    Scans for sensitive and backup files

    Identifies Joomla generator meta tags

    Detects common WAFs (e.g., Cloudflare, Sucuri)

    Dork-based discovery using DuckDuckGo

    Clear, color-coded output for quick analysis

⚠️ Disclaimer

This tool is for educational and authorized testing only. Use it responsibly.
The author is not responsible for any misuse.
