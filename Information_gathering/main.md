# WHOIS
- ```whois $TARGET```:	WHOIS lookup for the target.

# NSlookup and DIG
- ```nslookup $TARGET```: Identify the A record for the target domain.
- ```nslookup -query=A $TARGET```: Identify the A record for the target domain.
- ```dig $TARGET @<nameserver/IP>```: Identify the A record for the target domain.
- ```dig a $TARGET @<nameserver/IP>```: Identify the A record for the target domain.
- ```nslookup -query=PTR <IP>```: Identify the PTR record for the target IP address.
- ```dig -x <IP> @<nameserver/IP>```: Identify the PTR record for the target IP address.
- ```nslookup -query=ANY $TARGET```: Identify ANY records for the target domain.
- ```dig any $TARGET @<nameserver/IP>```: Identify ANY records for the target domain.
- ```nslookup -query=TXT $TARGET```: Identify the TXT records for the target domain.
- ```dig txt $TARGET @<nameserver/IP>```: Identify the TXT records for the target domain.
- ```nslookup -query=MX $TARGET```: Identify the MX records for the target domain.
- ```dig mx $TARGET @<nameserver/IP>```: Identify the MX records for the target domain.

# Passive subdomain enum
- **VirusTotal**: https://www.virustotal.com/gui/home/url
- ```cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b ${source} -f "${source}-${TARGET}";done```: Searching for subdomains and other information on the sources provided in the source.txt list.

# Passive infrastructure enumeration
- **WayBackMachine**: http://web.archive.org/

# Active infrastructure identification
-  ```curl -I "http://${TARGET}"```: we use this to identify the webserver version and technology.

There are also other characteristics to take into account while fingerprinting web servers in the response headers. These are:

- **X-Powered-By header**: This header can tell us what the web app is using. We can see values like PHP, ASP.NET, JSP, etc.

- **Cookies**: Cookies are another attractive value to look at as each technology by default has its cookies. Some of the default cookie values are:

- .NET: ASPSESSIONID<RANDOM>=<COOKIE_VALUE>
- PHP: PHPSESSID=<COOKIE_VALUE>
- JAVA: JSESSION=<COOKIE_VALUE>


## Whatweb
Whatweb recognizes web technologies, including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices.

Example of command: ```whatweb -a3 https://www.example.com -v```.

## WafWOOf
WafW00f is a web application firewall (WAF) fingerprinting tool that sends requests and analyses responses to determine if a security solution is in place.

We can use options like **-a** to check all possible WAFs in place instead of stopping scanning at the first match, read targets from an input file via the **-i** flag, or proxy the requests using the **-p** option.

Example of command: ```wafw00f -v https://www.example.com```.

## Aquatone
Aquatone is a tool for automatic and visual inspection of websites across many hosts and is convenient for quickly gaining an overview of HTTP-based attack surfaces by scanning a list of configurable ports, visiting the website with a headless Chrome browser, and taking a screenshot. This is helpful, especially when dealing with huge subdomain lists.

Use cat in our subdomain list and pipe the command to aquatone via: ```cat example_aquatone.txt | aquatone -out ./aquatone -screenshot-timeout 1000```.

When it finishes, we will have a file called aquatone_report.html where we can see screenshots, technologies identified, server response headers, and HTML.

# Active subdomain enumeration
The zone transfer is how a secondary DNS server receives information from the primary DNS server and updates it. The master-slave approach is used to organize DNS servers within a domain, with the slaves receiving updated DNS information from the master DNS. The master DNS server should be configured to enable zone transfers from secondary (slave) DNS servers, although this might be misconfigured.

Sequence of commands to perform zone transfer:
```
nslookup -type=NS zonetranfer.me.

nslookup -type=any -query=AXFR zonetransfer.me nsztm1.digi.ninja.
```

## Gobuster

Gobuster is a tool that we can use to perform subdomain enumeration. It is especially interesting for us the patterns options as we have learned some naming conventions from the passive information gathering we can use to discover new subdomains following the same pattern.

We can use a wordlist from Seclists repository along with gobuster if we are looking for words in patterns instead of numbers.

If there is a subdomains pattern that we identify, we can use it to discover additional ones. The first step will be to create a "patterns.txt" file with the patterns previously dicovered. Example:
- lert-api-shv-{GOBUSTER}-sin6
- atlas-pp-shv-{GOBUSTER}-sin6

The next step will be to launch gobuster using the dns module, specifying the following options:

- dns: Launch the DNS module.
- q: Don't print the banner and other noise.
- r: Use custom DNS server
- d: A target domain name
- p: Path to the patterns file
- w: Path to the wordlist
- o: Output file

Example of usage:
```
export TARGET="example.com"

export NS="d.ns.example.com"

export WORDLIST="numbers.txt"

gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"
```

# Virtual hosts
A virtual host (vHost) is a feature that allows several websites to be hosted on a single server. This is an excellent solution if you have many websites and don't want to go through the time-consuming (and expensive) process of setting up a new web server for each one. Imagine having to set up a different webserver for a mobile and desktop version of the same page. There are two ways to configure virtual hosts:

- IP-based virtual hosting
- Name-based virtual hosting

## Certificate trasparency

Certificate Transparency (CT) logs are public, append-only ledgers that record the issuance of SSL/TLS certificates. Whenever a Certificate Authority (CA) issues a new certificate, it must submit it to multiple CT logs. Independent organisations maintain these logs and are open for anyone to inspect.

Think of CT logs as a global registry of certificates. They provide a transparent and verifiable record of every SSL/TLS certificate issued for a website. This transparency serves several crucial purposes:

- Early Detection of Rogue Certificates: By monitoring CT logs, security researchers and website owners can quickly identify suspicious or misissued certificates. A rogue certificate is an unauthorized or fraudulent digital certificate issued by a trusted certificate authority. Detecting these early allows for swift action to revoke the certificates before they can be used for malicious purposes.
- Accountability for Certificate Authorities: CT logs hold CAs accountable for their issuance practices. If a CA issues a certificate that violates the rules or standards, it will be publicly visible in the logs, leading to potential sanctions or loss of trust.
- Strengthening the Web PKI (Public Key Infrastructure): The Web PKI is the trust system underpinning secure online communication. CT logs help to enhance the security and integrity of the Web PKI by providing a mechanism for public oversight and verification of certificates.

# How certificate transparency logs works
Certificate Transparency logs rely on a clever combination of cryptographic techniques and public accountability:

1. Certificate Issuance: When a website owner requests an SSL/TLS certificate from a Certificate Authority (CA), the CA performs due diligence to verify the owner's identity and domain ownership. Once verified, the CA issues a pre-certificate, a preliminary certificate version;
2. Log Submission: The CA then submits this pre-certificate to multiple CT logs. Each log is operated by a different organisation, ensuring redundancy and decentralisation. The logs are essentially append-only, meaning that once a certificate is added, it cannot be modified or deleted, ensuring the integrity of the historical record;
3. Signed Certificate Timestamp (SCT): Upon receiving the pre-certificate, each CT log generates a Signed Certificate Timestamp (SCT). This SCT is a cryptographic proof that the certificate was submitted to the log at a specific time. The SCT is then included in the final certificate issued to the website owner;
4. Browser Verification: When a user's browser connects to a website, it checks the certificate's SCTs. These SCTs are verified against the public CT logs to confirm that the certificate was issued and logged correctly. If the SCTs are valid, the browser establishes a secure connection; if not, it may display a warning to the user;
5. Monitoring and Auditing: CT logs are continuously monitored by various entities, including security researchers, website owners, and browser vendors. These monitors look for anomalies or suspicious certificates, such as those issued for domains they don't own or certificates violating industry standards. If any issues are found, they can be reported to the relevant CA for investigation and potential revocation of the certificate.

# The merkle tree structure

To ensure CT logs' integrity and tamper-proof nature, they employ a Merkle tree cryptographic structure. This structure organises the certificates in a tree-like fashion, where each leaf node represents a certificate, and each non-leaf node represents a hash of its child nodes. The root of the tree, known as the Merkle root, is a single hash representing the entire log.

```
curl -s "https://crt.sh/?q=example.com&output=json" | jq -r '.[]
 | select(.name_value | contains("dev")) | .name_value' | sort -u
```
# Banner grabbing

```curl -I example.com```

# Nikto

Nikto is a powerful open-source web server scanner. In addition to its primary function as a vulnerability assessment tool, Nikto's fingerprinting capabilities provide insights into a website's technology stack.

```nikto -h example.com```

# Crawling
- OWASP ZAP

# Google dorking

Google Dorking, also known as Google Hacking, is a technique that leverages the power of search operators to uncover sensitive information, security vulnerabilities, or hidden content on websites, using Google Search.

- Refer to **Google Hacking Database** for all the queries.

# Automating recon

- **Final Recon**: A Python-based reconnaissance tool offering a range of modules for different tasks like SSL certificate checking, Whois information gathering, header analysis, and crawling. Its modular structure enables easy customisation for specific needs;
- **TheHarvester**:  Specifically designed for gathering email addresses, subdomains, hosts, employee names, open ports, and banners from different public sources like search engines, PGP key servers, and the SHODAN database. It is a command-line tool written in Python.
