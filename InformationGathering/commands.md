# WHOIS
- **whois $TARGET**:	WHOIS lookup for the target.

# NSlookup and DIG
- **nslookup $TARGET**: Identify the A record for the target domain.
- **nslookup -query=A $TARGET**: Identify the A record for the target domain.
- **dig $TARGET @<nameserver/IP>**: Identify the A record for the target domain.
- **dig a $TARGET @<nameserver/IP>**: Identify the A record for the target domain.
- **nslookup -query=PTR <IP>**: Identify the PTR record for the target IP address.
- **dig -x <IP> @<nameserver/IP>**: Identify the PTR record for the target IP address.
- **nslookup -query=ANY $TARGET**: Identify ANY records for the target domain.
- **dig any $TARGET @<nameserver/IP>**: Identify ANY records for the target domain.
- **nslookup -query=TXT $TARGET**: Identify the TXT records for the target domain.
- **dig txt $TARGET @<nameserver/IP>**: Identify the TXT records for the target domain.
- **nslookup -query=MX $TARGET**: Identify the MX records for the target domain.
- **dig mx $TARGET @<nameserver/IP>**: Identify the MX records for the target domain.

# Passive subdomain enum
- **VirusTotal**: https://www.virustotal.com/gui/home/url
- **cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b ${source} -f "${source}-${TARGET}";done**: Searching for subdomains and other information on the sources provided in the source.txt list.

# Passive infrastructure enumeration
- **WayBackMachine**: http://web.archive.org/

# Active infrastructure identification
-  **curl -I "http://${TARGET}"**: we use this to identify the webserver version and technology.

There are also other characteristics to take into account while fingerprinting web servers in the response headers. These are:

- **X-Powered-By header**: This header can tell us what the web app is using. We can see values like PHP, ASP.NET, JSP, etc.

- **Cookies**: Cookies are another attractive value to look at as each technology by default has its cookies. Some of the default cookie values are:

.NET: ASPSESSIONID<RANDOM>=<COOKIE_VALUE>
PHP: PHPSESSID=<COOKIE_VALUE>
JAVA: JSESSION=<COOKIE_VALUE>


## Whatweb
Whatweb recognizes web technologies, including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices.

Example of command: **whatweb -a3 https://www.facebook.com -v**.

## WafWOOf
WafW00f is a web application firewall (WAF) fingerprinting tool that sends requests and analyses responses to determine if a security solution is in place.

We can use options like **-a** to check all possible WAFs in place instead of stopping scanning at the first match, read targets from an input file via the **-i** flag, or proxy the requests using the **-p** option.

Example of command: **wafw00f -v https://www.tesla.com**.

## Aquatone
Aquatone is a tool for automatic and visual inspection of websites across many hosts and is convenient for quickly gaining an overview of HTTP-based attack surfaces by scanning a list of configurable ports, visiting the website with a headless Chrome browser, and taking a screenshot. This is helpful, especially when dealing with huge subdomain lists.

Use cat in our subdomain list and pipe the command to aquatone via: **cat facebook_aquatone.txt | aquatone -out ./aquatone -screenshot-timeout 1000**.

When it finishes, we will have a file called aquatone_report.html where we can see screenshots, technologies identified, server response headers, and HTML.

# Active subdomain enumeration
The zone transfer is how a secondary DNS server receives information from the primary DNS server and updates it. The master-slave approach is used to organize DNS servers within a domain, with the slaves receiving updated DNS information from the master DNS. The master DNS server should be configured to enable zone transfers from secondary (slave) DNS servers, although this might be misconfigured.

Sequence of commands to perform zone transfer:
- nslookup -type=NS zonetranfer.me.
- nslookup -type=any -query=AXFR zonetransfer.me nsztm1.digi.ninja.

## Gobuster

Gobuster is a tool that we can use to perform subdomain enumeration. It is especially interesting for us the patterns options as we have learned some naming conventions from the passive information gathering we can use to discover new subdomains following the same pattern.

We can use a wordlist from Seclists repository along with gobuster if we are looking for words in patterns instead of numbers.

If there is a subdomains pattern that we identify, we can use it to discover additional ones. The first step will be to create a "patterns.txt" file with the patterns previously dicovered. Example:
- lert-api-shv-{GOBUSTER}-sin6
- atlas-pp-shv-{GOBUSTER}-sin6

The next step will be to launch gobuster using the dns module, specifying the following options:

- dns: Launch the DNS module.
-q: Don't print the banner and other noise.
-r: Use custom DNS server
-d: A target domain name
-p: Path to the patterns file
-w: Path to the wordlist
-o: Output file

Example of usage:
- export TARGET="facebook.com"
- export NS="d.ns.facebook.com"
- export WORDLIST="numbers.txt"
- gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"
