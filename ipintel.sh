#!/usr/bin/env bash
# =============================================================================
# ip_intel.sh — IP Intelligence Lookup Tool
# Queries: ARIN, APNIC, RIPE, MERIT/RADB, ASN, Abuse Contact, ISP/Owner,
#          AbuseIPDB Blacklist Score
#
# Usage:
#   Single IP:         ./ip_intel.sh 8.8.8.8
#   IP list file:      ./ip_intel.sh -f ip_list.txt
#   With API key flag: ./ip_intel.sh -k YOUR_API_KEY 8.8.8.8
#   With key file:     ./ip_intel.sh 8.8.8.8        (auto-reads ~/.ip_intel.conf)
#
# API Key File (~/.ip_intel.conf):
#   ABUSEIPDB_KEY=your_api_key_here
#
# Dependencies: curl, whois, jq (optional but recommended)
# Compatible with: macOS (Bash 3.2+) and Linux
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ABUSEIPDB_KEY=""
IP_FILE=""
IPS=()

# Default config file location (can be overridden with -c)
CONFIG_FILE="${HOME}/.ip_intel.conf"

# =============================================================================
# load_config — reads API keys from a config file
# Supported locations (in order of priority):
#   1. -c /path/to/file   (explicit flag)
#   2. ~/.ip_intel.conf   (default user config)
#   3. ./ip_intel.conf    (local directory fallback)
#
# Config file format (one per line, # comments supported):
#   ABUSEIPDB_KEY=your_key_here
# =============================================================================
load_config() {
  local config_locations=("$CONFIG_FILE" "./ip_intel.conf")

  for cfg in "${config_locations[@]}"; do
    if [[ -f "$cfg" ]]; then
      echo -e "${GREEN}  Loading config: ${cfg}${RESET}"
      while IFS= read -r line || [[ -n "$line" ]]; do
        # Strip inline comments and whitespace
        line="${line%%#*}"
        line="${line//[[:space:]]/}"
        [[ -z "$line" ]] && continue

        # Parse KEY=VALUE pairs
        if [[ "$line" =~ ^ABUSEIPDB_KEY=(.+)$ ]]; then
          # Only load from file if not already set via -k flag
          if [[ -z "$ABUSEIPDB_KEY" ]]; then
            ABUSEIPDB_KEY="${BASH_REMATCH[1]}"
            echo -e "${GREEN}  AbuseIPDB key loaded from config file.${RESET}"
          else
            echo -e "${YELLOW}  AbuseIPDB key from -k flag takes priority over config file.${RESET}"
          fi
        fi
      done < "$cfg"
      return 0
    fi
  done

  # No config file found — not an error, key can still be passed via -k
  return 0
}

# =============================================================================
# create_config — interactively create a config file
# Triggered with: ./ip_intel.sh --setup
# =============================================================================
create_config() {
  echo -e "\n${BOLD}${CYAN}[ API Key Setup ]${RESET}"
  echo -e "This will create: ${BOLD}${CONFIG_FILE}${RESET}\n"
  echo -e "Get a free AbuseIPDB API key at: ${CYAN}https://www.abuseipdb.com${RESET}"
  echo -e "(Free tier: 50,000 checks/month)\n"

  read -r -p "Enter your AbuseIPDB API key (or press Enter to skip): " input_key

  if [[ -z "$input_key" ]]; then
    echo -e "${YELLOW}No key entered. Skipping config creation.${RESET}"
    exit 0
  fi

  # Write config file with restricted permissions (owner read/write only)
  cat > "$CONFIG_FILE" <<EOF
# ip_intel.sh configuration file
# Generated: $(date)
# Protect this file — it contains API keys.

ABUSEIPDB_KEY=${input_key}
EOF

  chmod 600 "$CONFIG_FILE"
  echo -e "\n${GREEN}Config saved to: ${CONFIG_FILE}${RESET}"
  echo -e "${GREEN}Permissions set to 600 (owner read/write only).${RESET}\n"
  exit 0
}

usage() {
  echo -e "${BOLD}Usage:${RESET}"
  echo "  $(basename "$0") [OPTIONS] [IP_ADDRESS ...]"
  echo ""
  echo -e "${BOLD}Options:${RESET}"
  echo "  -f <file>    File containing one IP address per line"
  echo "  -k <apikey>  AbuseIPDB API key (overrides config file)"
  echo "  -c <file>    Path to a custom config file"
  echo "  --setup      Interactively create ~/.ip_intel.conf with your API key"
  echo "  -h           Show this help message"
  echo ""
  echo -e "${BOLD}Config File (~/.ip_intel.conf):${RESET}"
  echo "  ABUSEIPDB_KEY=your_key_here"
  echo ""
  echo -e "${BOLD}Examples:${RESET}"
  echo "  $(basename "$0") --setup"
  echo "  $(basename "$0") 8.8.8.8"
  echo "  $(basename "$0") -k MY_API_KEY 1.1.1.1 8.8.4.4"
  echo "  $(basename "$0") -c /etc/ip_intel.conf -f ips.txt"
  exit 0
}

# Handle --setup and --help before getopts (long option support)
for arg in "$@"; do
  case "$arg" in
    --setup) create_config ;;
    --help)  usage ;;
  esac
done

while getopts ":f:k:c:h" opt; do
  case $opt in
    f) IP_FILE="$OPTARG" ;;
    k) ABUSEIPDB_KEY="$OPTARG" ;;
    c) CONFIG_FILE="$OPTARG" ;;
    h) usage ;;
    :) echo "Option -$OPTARG requires an argument." >&2; exit 1 ;;
    \?) echo "Unknown option: -$OPTARG" >&2; exit 1 ;;
  esac
done
shift $((OPTIND - 1))

for arg in "$@"; do
  IPS+=("$arg")
done

if [[ -n "$IP_FILE" ]]; then
  if [[ ! -f "$IP_FILE" ]]; then
    echo -e "${RED}Error: File '$IP_FILE' not found.${RESET}" >&2
    exit 1
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line// /}"
    [[ -z "$line" ]] && continue
    IPS+=("$line")
  done < "$IP_FILE"
fi

if [[ ${#IPS[@]} -eq 0 ]]; then
  echo -e "${RED}Error: No IP addresses provided.${RESET}"
  usage
fi

check_deps() {
  local missing=()
  for cmd in curl whois; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo -e "${RED}Missing required tools: ${missing[*]}${RESET}"
    echo "Install with: brew install ${missing[*]}   (macOS)"
    echo "          or: sudo apt install ${missing[*]}   (Debian/Ubuntu)"
    exit 1
  fi
  if ! command -v jq &>/dev/null; then
    echo -e "${YELLOW}Warning: 'jq' not found. JSON output will be raw.${RESET}"
    echo -e "${YELLOW}Install: brew install jq  /  apt install jq${RESET}"
  fi
}

separator() {
  echo -e "${CYAN}$(printf '─%.0s' {1..70})${RESET}"
}

validate_ip() {
  local ip="$1"
  local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
  if [[ ! $ip =~ $regex ]]; then return 1; fi
  IFS='.' read -ra octets <<< "$ip"
  for o in "${octets[@]}"; do
    (( o >= 0 && o <= 255 )) || return 1
  done
  return 0
}

whois_lookup() {
  local ip="$1"
  echo -e "\n${BOLD}${CYAN}[ WHOIS — RIR Data (ARIN/RIPE/APNIC/LACNIC/AFRINIC) ]${RESET}"
  local raw
  raw=$(whois "$ip" 2>/dev/null) || { echo -e "${RED}whois lookup failed${RESET}"; return; }

  echo "$raw" | grep -iE \
    "(NetName|netname|inetnum|NetRange|CIDR|Organization|OrgName|org-name|descr|country|RegDate|Updated|Ref:|source:|NetType|aut-num|ASName)" \
    | head -40 | sed 's/^/  /'

  local rir=""
  if echo "$raw" | grep -qi "arin.net";    then rir="ARIN";    fi
  if echo "$raw" | grep -qi "ripe.net";    then rir="RIPE";    fi
  if echo "$raw" | grep -qi "apnic.net";   then rir="APNIC";   fi
  if echo "$raw" | grep -qi "lacnic.net";  then rir="LACNIC";  fi
  if echo "$raw" | grep -qi "afrinic.net"; then rir="AFRINIC"; fi
  [[ -n "$rir" ]] && echo -e "\n  ${GREEN}Authoritative RIR: $rir${RESET}"
}

arin_lookup() {
  local ip="$1"
  echo -e "\n${BOLD}${CYAN}[ ARIN REST API ]${RESET}"
  local resp
  resp=$(curl -s --max-time 10 \
    -H "Accept: application/json" \
    "https://whois.arin.net/rest/ip/${ip}.json") || { echo -e "${RED}ARIN API request failed${RESET}"; return; }

  if command -v jq &>/dev/null; then
    echo "$resp" | jq -r '
      .net |
      "  Name:        " + (.name // "N/A"),
      "  Handle:      " + (.handle // "N/A"),
      "  Net Range:   " + (.startAddress // "N/A") + " - " + (.endAddress // "N/A"),
      "  Org:         " + (.orgRef."@name" // "N/A"),
      "  Reg Date:    " + (.registrationDate // "N/A"),
      "  Updated:     " + (.updateDate // "N/A"),
      "  Ref:         " + (.ref."$" // "N/A")
    ' 2>/dev/null || echo "  (No ARIN data — may be RIPE/APNIC address space)"
  else
    echo "$resp" | grep -oE '"(name|handle|startAddress|endAddress)":"[^"]+"' | sed 's/^/  /' | head -10
  fi
}

ripe_lookup() {
  local ip="$1"
  echo -e "\n${BOLD}${CYAN}[ RIPE Stat — Prefix and Routing Info ]${RESET}"
  local resp
  resp=$(curl -s --max-time 10 \
    "https://stat.ripe.net/data/prefix-overview/data.json?resource=${ip}") || {
    echo -e "${RED}RIPE Stat request failed${RESET}"; return; }

  if command -v jq &>/dev/null; then
    echo "$resp" | jq -r '
      .data |
      "  Resource:    " + (.resource // "N/A"),
      "  ASNs:        " + ([.asns[]? | "AS" + (.asn|tostring) + " (" + .holder + ")"] | join(", ")),
      "  Block:       " + (.block.resource // "N/A") + " - " + (.block.name // "N/A")
    ' 2>/dev/null || echo "  (No RIPE data for this IP)"
  else
    echo "$resp" | grep -oE '"resource":"[^"]+"' | head -5 | sed 's/^/  /'
  fi
}

merit_radb_lookup() {
  local ip="$1"
  echo -e "\n${BOLD}${CYAN}[ MERIT / RADB — Internet Routing Registry ]${RESET}"
  local resp
  resp=$(whois -h whois.radb.net "$ip" 2>/dev/null) || {
    echo -e "${RED}RADB whois failed${RESET}"; return; }

  echo "$resp" | grep -iE \
    "(route|origin|descr|mnt-by|source|changed|remarks)" \
    | head -20 | sed 's/^/  /' \
    || echo "  (No RADB routing record found)"
}

asn_lookup() {
  local ip="$1"
  echo -e "\n${BOLD}${CYAN}[ ASN / ISP / Owner — ipinfo.io ]${RESET}"
  local resp
  resp=$(curl -s --max-time 10 "https://ipinfo.io/${ip}/json") || {
    echo -e "${RED}ipinfo.io request failed${RESET}"; return; }

  if command -v jq &>/dev/null; then
    echo "$resp" | jq -r '
      "  IP:          " + (.ip // "N/A"),
      "  Hostname:    " + (.hostname // "N/A"),
      "  ASN / Org:   " + (.org // "N/A"),
      "  City:        " + (.city // "N/A"),
      "  Region:      " + (.region // "N/A"),
      "  Country:     " + (.country // "N/A"),
      "  Postal:      " + (.postal // "N/A"),
      "  Timezone:    " + (.timezone // "N/A")
    ' 2>/dev/null || echo "  (Unable to parse ipinfo.io response)"
  else
    echo "$resp" | grep -oE '"(ip|hostname|org|city|region|country|postal|timezone)":"[^"]+"' | sed 's/^/  /'
  fi
}

abuse_contact_lookup() {
  local ip="$1"
  echo -e "\n${BOLD}${CYAN}[ Abuse Contact ]${RESET}"
  local abuse_email
  abuse_email=$(whois "$ip" 2>/dev/null | grep -iE "^(OrgAbuseEmail|abuse-mailbox|abuse):" | \
    awk '{print $2}' | head -3) || true
  if [[ -n "$abuse_email" ]]; then
    echo "  Abuse Email: $abuse_email"
  else
    echo "  (No abuse email found in whois)"
  fi
}

abuseipdb_check() {
  local ip="$1"
  echo -e "\n${BOLD}${CYAN}[ AbuseIPDB — Blacklist / Threat Score ]${RESET}"

  if [[ -z "$ABUSEIPDB_KEY" ]]; then
    echo -e "  ${YELLOW}Skipped — no API key found.${RESET}"
    echo -e "  ${YELLOW}Run './ip_intel.sh --setup' to save your key, or use -k YOUR_KEY${RESET}"
    echo -e "  ${YELLOW}Get a free key at: https://www.abuseipdb.com${RESET}"
    return
  fi

  local resp
  resp=$(curl -s --max-time 10 -G "https://api.abuseipdb.com/api/v2/check" \
    --data-urlencode "ipAddress=${ip}" \
    -d maxAgeInDays=90 \
    -H "Key: ${ABUSEIPDB_KEY}" \
    -H "Accept: application/json") || {
    echo -e "${RED}AbuseIPDB request failed${RESET}"; return; }

  if command -v jq &>/dev/null; then
    local score
    score=$(echo "$resp" | jq -r '.data.abuseConfidenceScore // 0')
    local score_color="$GREEN"
    if (( score > 25 )); then score_color="$YELLOW"; fi
    if (( score > 75 )); then score_color="$RED"; fi

    echo -e "  Abuse Score:    ${score_color}${BOLD}${score}%${RESET}"
    echo "$resp" | jq -r '
      "  ISP:            " + (.data.isp // "N/A"),
      "  Domain:         " + (.data.domain // "N/A"),
      "  Usage Type:     " + (.data.usageType // "N/A"),
      "  Total Reports:  " + (.data.totalReports // 0 | tostring),
      "  Last Reported:  " + (.data.lastReportedAt // "Never"),
      "  Whitelisted:    " + (.data.isWhitelisted // false | tostring)
    ' 2>/dev/null
  else
    echo "$resp" | grep -oE '"(abuseConfidenceScore|isp|totalReports|usageType)":"?[^",}]+"?' | sed 's/^/  /'
  fi
}

rdns_lookup() {
  local ip="$1"
  echo -e "\n${BOLD}${CYAN}[ Reverse DNS (PTR Record) ]${RESET}"
  local rdns
  rdns=$(host "$ip" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}') || true
  if [[ -n "$rdns" ]]; then
    echo "  PTR: $rdns"
  else
    rdns=$(curl -s --max-time 5 "https://ipinfo.io/${ip}/hostname" 2>/dev/null) || true
    [[ -n "$rdns" ]] && echo "  PTR: $rdns" || echo "  (No PTR record found)"
  fi
}

lookup_ip() {
  local ip="$1"
  separator
  echo -e "${BOLD}${GREEN}  IP INTELLIGENCE REPORT: ${ip}${RESET}"
  separator
  whois_lookup         "$ip"
  arin_lookup          "$ip"
  ripe_lookup          "$ip"
  merit_radb_lookup    "$ip"
  asn_lookup           "$ip"
  abuse_contact_lookup "$ip"
  abuseipdb_check      "$ip"
  rdns_lookup          "$ip"
  separator
  echo ""
}

# =============================================================================
# Main
# =============================================================================
check_deps
load_config   # Load API keys from config file before running lookups

echo -e "${BOLD}${GREEN}"
echo "  ██╗██████╗     ██╗███╗   ██╗████████╗███████╗██╗     "
echo "  ██║██╔══██╗    ██║████╗  ██║╚══██╔══╝██╔════╝██║     "
echo "  ██║██████╔╝    ██║██╔██╗ ██║   ██║   █████╗  ██║     "
echo "  ██║██╔═══╝     ██║██║╚██╗██║   ██║   ██╔══╝  ██║     "
echo "  ██║██║         ██║██║ ╚████║   ██║   ███████╗███████╗"
echo "  ╚═╝╚═╝         ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝"
echo -e "${RESET}"
echo -e "  ${CYAN}ARIN · RIPE · APNIC · MERIT/RADB · AbuseIPDB · ASN · rDNS${RESET}\n"

for ip in "${IPS[@]}"; do
  if ! validate_ip "$ip"; then
    echo -e "${RED}Skipping invalid IP: '$ip'${RESET}"
    continue
  fi
  lookup_ip "$ip"
done
