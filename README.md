==================================================
 ip_intel.sh - IP Intelligence Lookup Tool
 README
==================================================


OVERVIEW
--------
A powerful, dependency-light Bash script for security analysts, network
engineers, and sysadmins that performs comprehensive IP address intelligence
lookups directly from the command line. Compatible with macOS and Linux.


FEATURES
--------
- WHOIS / RIR Lookup        Queries the correct Regional Internet Registry
                            automatically (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
- ARIN REST API             Structured network block, organization, and
                            registration data
- RIPE Stat                 Prefix overview, announced ASNs, routing block info
- MERIT / RADB              Internet Routing Registry route objects and origin ASN
- ASN / ISP / Owner         ASN, ISP name, and organization via ipinfo.io
- Abuse Contact             Extracts abuse email addresses from WHOIS records
- AbuseIPDB Blacklist Score Threat confidence score, total reports, usage type,
                            and last reported date (requires free API key)
- Reverse DNS (PTR)         Resolves hostname from IP address
- Single or Bulk IP support Pass IPs as arguments or load from a file
- API Key Management        Securely store your AbuseIPDB key in a config file
- Color-coded output        Abuse scores highlighted green / yellow / red
- Save to file              Use -o report.txt to save clean plain text output


REQUIREMENTS
------------
Tool      Required    Purpose
--------  ----------  -------------------------
curl      Yes         API requests
whois     Yes         RIR and RADB lookups
jq        No*         Pretty JSON parsing
host      No*         Reverse DNS (PTR) resolution

* Strongly recommended. Without jq, raw JSON is displayed.
  host is pre-installed on most systems.

Install missing tools:

  macOS:
    brew install curl whois jq

  Debian / Ubuntu:
    sudo apt install curl whois jq dnsutils


INSTALLATION
------------
1. Save the script to a file:
     nano ip_intel.sh
     (paste script content, then Ctrl+O to save, Ctrl+X to exit)

2. Make it executable:
     chmod +x ip_intel.sh

3. (Optional) Move to your PATH for global use:
     sudo mv ip_intel.sh /usr/local/bin/ip_intel


API KEY SETUP (AbuseIPDB)
--------------------------
The script integrates with AbuseIPDB for blacklist and threat scoring.
A free account provides 50,000 checks per month.
Get your free key at: https://www.abuseipdb.com

Option 1 - Interactive Setup (Recommended):
  ./ip_intel.sh --setup
  Saves your key to ~/.ip_intel.conf with chmod 600 permissions.
  The key loads automatically on every subsequent run.

Option 2 - Manual Config File:
  Create ~/.ip_intel.conf with the following content:

    # ip_intel.sh configuration
    ABUSEIPDB_KEY=your_api_key_here

  Then set safe permissions:
    chmod 600 ~/.ip_intel.conf

Option 3 - Inline Flag (one-off use):
  ./ip_intel.sh -k YOUR_API_KEY 8.8.8.8

Priority order: -k flag > config file.
The -k flag always wins if both are present.


USAGE
-----
  ./ip_intel.sh [OPTIONS] [IP_ADDRESS ...]

Options:
  -f <file>    File containing one IP address per line
  -o <file>    Save output to a text file (also prints to CLI)
  -k <apikey>  AbuseIPDB API key (overrides config file)
  -c <file>    Path to a custom config file
  --setup      Interactive wizard to create ~/.ip_intel.conf
  -h / --help  Show help message

Examples:
  ./ip_intel.sh --setup
  ./ip_intel.sh 8.8.8.8
  ./ip_intel.sh 1.1.1.1 45.33.32.156 198.51.100.1
  ./ip_intel.sh -f ip_list.txt
  ./ip_intel.sh -o report.txt 8.8.8.8
  ./ip_intel.sh -f ip_list.txt -o scan_report.txt
  ./ip_intel.sh -k MY_ABUSEIPDB_KEY -o report.txt 8.8.8.8
  ./ip_intel.sh -c /etc/ip_intel.conf -f ips.txt
  ./ip_intel.sh -o "report_$(date +%Y%m%d_%H%M%S).txt" 8.8.8.8

IP List File Format (ip_list.txt):
  # Internal suspects
  192.168.1.100
  45.33.32.156    # Known scanner

  # External sources
  8.8.8.8
  1.1.1.1

  Blank lines and # comments are ignored automatically.


HOW IT WORKS
------------
Each IP address goes through a pipeline of 8 lookup functions:

  IP Address
      |
      +-- 1. WHOIS (native binary)
      |         Queries correct RIR via referral chain
      |         Auto-detects: ARIN / RIPE / APNIC / LACNIC / AFRINIC
      |
      +-- 2. ARIN REST API
      |         https://whois.arin.net/rest/ip/{IP}.json
      |         Returns: net name, handle, org, date range, net block
      |
      +-- 3. RIPE Stat
      |         https://stat.ripe.net/data/prefix-overview/
      |         Returns: prefix, announced ASNs, block name
      |
      +-- 4. MERIT / RADB
      |         whois -h whois.radb.net {IP}
      |         Returns: IRR route objects, origin ASN, maintainer
      |
      +-- 5. ASN / ISP / Owner
      |         https://ipinfo.io/{IP}/json
      |         Returns: ASN, ISP, city, country, timezone
      |
      +-- 6. Abuse Contact
      |         Parses OrgAbuseEmail / abuse-mailbox from WHOIS
      |
      +-- 7. AbuseIPDB Threat Score
      |         https://api.abuseipdb.com/api/v2/check
      |         Returns: confidence score, reports, usage type
      |         Color coded: Green (0-25%) Yellow (26-75%) Red (76-100%)
      |
      +-- 8. Reverse DNS (PTR)
                host {IP} -> PTR record
                Fallback: https://ipinfo.io/{IP}/hostname


OUTPUT FILE
-----------
Use the -o flag to save a clean copy of the report to a text file.
ANSI color codes are automatically stripped from the saved file so it
reads cleanly in any text editor, email client, or ticketing system.
A timestamped header is written at the top of each saved report.

  ./ip_intel.sh -o report.txt 8.8.8.8

  # Auto-timestamped filename (keeps history of scans)
  ./ip_intel.sh -o "report_$(date +%Y%m%d_%H%M%S).txt" -f ip_list.txt


SECURITY NOTES
--------------
- The config file is created with chmod 600 (owner read/write only)
- Never commit ~/.ip_intel.conf or any file containing your API key
  to version control
- Add ip_intel.conf to your .gitignore if storing the script in a repo
- The -k flag exposes your key in shell history — prefer the config
  file for regular use


RIR REFERENCE
-------------
Registry    Region                  Website
----------  ----------------------  ------------------
ARIN        North America           whois.arin.net
RIPE NCC    Europe / Middle East    whois.ripe.net
APNIC       Asia-Pacific            whois.apnic.net
LACNIC      Latin America           whois.lacnic.net
AFRINIC     Africa                  whois.afrinic.net
MERIT/RADB  Global IRR              whois.radb.net


LICENSE
-------
MIT License - free to use, modify, and distribute.


CONTRIBUTING
------------
To add support for additional threat intelligence sources such as
VirusTotal, Shodan, or Greynoise, add a new _lookup() function following
the existing pattern and call it inside lookup_ip().

==================================================
 End of README
==================================================
