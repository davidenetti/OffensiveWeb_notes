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
- **cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}-${TARGET}";done**: Searching for subdomains and other information on the sources provided in the source.txt list.

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
