# toolchain.local.ps1
# Local toolchain configuration — copy from this template and customize
# DO NOT commit this file (it is in .gitignore)

# === External tools (adjust paths for your system) ===
$env:MINA_NMAP_PATH    = "nmap"          # Full path if not in PATH
$env:MINA_SUBFINDER_PATH = "subfinder"   # Full path if not in PATH
$env:MINA_HTTPX_PATH   = "httpx"         # Full path if not in PATH
$env:MINA_NUCLEI_PATH  = "nuclei"        # Full path if not in PATH
$env:MINA_FFUF_PATH    = "ffuf"          # Full path if not in PATH

# === API Keys (override .env if needed) ===
# $env:SHODAN_API_KEY    = "your-shodan-key-here"
# $env:DEEPSEEK_API_KEY  = "your-deepseek-key-here"

# === Optional: Wordlists (override defaults) ===
# $env:MINA_WORDLIST_SUBDOMAINS = "C:\tools\wordlists\subdomains-top1million.txt"
# $env:MINA_WORDLIST_DIRS       = "C:\tools\wordlists\directory-list-2.3-medium.txt"

# === Proxy settings (for Burp, ZAP, etc.) ===
# $env:HTTP_PROXY  = "http://127.0.0.1:8080"
# $env:HTTPS_PROXY = "http://127.0.0.1:8080"
# $env:NO_PROXY    = "localhost,127.0.0.1"

Write-Host "[toolchain.local] Loaded local toolchain overrides." -ForegroundColor Cyan
