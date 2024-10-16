The HTTP protocol works by accepting various HTTP methods as verbs at the beginning of an HTTP request. Depending on the web server configuration, web applications may be scripted to accept certain HTTP methods for their various functionalities and perform a particular action based on the type of the request.

While programmers mainly consider the two most commonly used HTTP methods, GET and POST, any client can send any other methods in their HTTP requests and then see how the web server handles these methods. **Suppose both the web application and the back-end web server are configured only to accept GET and POST requests. In that case, sending a different request will cause a web server error page to be displayed, which is not a severe vulnerability in itself** (other than providing a bad user experience and potentially leading to information disclosure).

On the other hand, **if the web server configurations are not restricted to only accept the HTTP methods required by the web server (e.g. GET/POST), and the web application is not developed to handle other types of HTTP requests (e.g. HEAD, PUT), then we may be able to exploit this insecure configuration to gain access to functionalities we do not have access to, or even bypass certain security controls**.

HTTP has 9 different verbs that can be accepted as HTTP methods by web servers. Other than GET and POST, the following are some of the commonly used HTTP verbs:
- HEAD: Identical to a GET request, but its response only contains the headers, without the response body;
- PUT: Writes the request payload to the specified location;
- DELETE: Deletes the resource at the specified location;
- OPTIONS: Shows different options accepted by a web server, like accepted HTTP verbs;
- PATCH: Apply partial modifications to the resource at the specified location.

# Insecure configurations

Insecure web server configurations cause the first type of HTTP Verb Tampering vulnerabilities. A web server's authentication configuration may be limited to specific HTTP methods, which would leave some HTTP methods accessible without authentication.

For example, a system admin may use the following configuration to require authentication on a particular web page:

```xml
<Limit GET POST>
    Require valid-user
</Limit>
```
As we can see, even though the configuration specifies both GET and POST requests for the authentication method, an attacker may still use a different HTTP method (like HEAD) to bypass this authentication mechanism altogether, as will see in the next section. This eventually leads to an authentication bypass and allows attackers to access web pages and domains they should not have access to.

# Insecure coding

Insecure coding practices cause the other type of HTTP Verb Tampering vulnerabilities (though some may not consider this Verb Tampering). **This can occur when a web developer applies specific filters to mitigate particular vulnerabilities while not covering all HTTP methods with that filter**.

For example, if a web page was found to be vulnerable to a SQL Injection vulnerability, and the back-end developer mitigated the SQL Injection vulnerability by the following applying input sanitization filters:

```php
$pattern = "/^[A-Za-z\s]+$/";

if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...SNIP...
}
```
We can see that the sanitization filter is only being tested on the GET parameter. If the GET requests do not contain any bad characters, then the query would be executed. However, when the query is executed, the ```$_REQUEST["code"]``` parameters are being used, which may also contain POST parameters, leading to an inconsistency in the use of HTTP Verbs. In this case, an attacker may use a POST request to perform SQL injection, in which case the GET parameters would be empty (will not include any bad characters). The request would pass the security filter, which would make the function still vulnerable to SQL Injection.

# Bypassing basic authentication

### Scenario
We have a web application which simulate a "File Manager" in which we can add new files by typing their names and hitting enter.
However, **suppose we try to delete all files by clicking on the red Reset button (in the GUI there is a red button "Reset" which seems to purge all the files in the filesystem)**. In that case, we see that this functionality seems to be restricted for authenticated users only, as we get the following HTTP Basic Auth prompt.

we need to identify **which pages are restricted** by this authentication. If we examine the HTTP request after clicking the Reset button or look at the URL that the button navigates to after clicking it, we see that it is at /admin/reset.php. So, either the /admin directory is restricted to authenticated users only, or only the /admin/reset.php page is. We can confirm this by visiting the /admin directory, and we do indeed get prompted to log in again. This means that the full **/admin directory is restricted**.

To try and exploit the page, we need to identify the HTTP request method used by the web application. **We can intercept the request in Burp Suite and examine it**.

As the page uses a GET request, we can send a POST request and see whether the web page allows POST requests (i.e., whether the Authentication covers POST requests). To do so, we can right-click on the intercepted request in Burp and select Change Request Method, and it will automatically change the request into a POST request

Once we do so, we can click Forward and examine the page in our browser. Unfortunately, we still get prompted to log in and will get a 401 Unauthorized page if we don't provide the credentials

So, it seems like the web server configurations do cover both GET and POST requests. However, as we have previously learned, we can utilize many other HTTP methods, most notably the **HEAD method**, which is identical to a GET request but does not return the body in the HTTP response. If this is successful, we may not receive any output, but the reset function should still get executed, which is our main target.

To see whether the server accepts HEAD requests, we can send an OPTIONS request to it and see what HTTP methods are accepted, as follows:

```bash
curl -i -X OPTIONS http://SERVER_IP:PORT/

HTTP/1.1 200 OK
Date: 
Server: Apache/2.4.41 (Ubuntu)
Allow: POST,OPTIONS,HEAD,GET
Content-Length: 0
Content-Type: httpd/unix-directory
```

Once we change POST to HEAD and forward the request, we will see that we no longer get a login prompt or a 401 Unauthorized page and get an empty output instead, as expected with a HEAD request. If we go back to the File Manager web application, we will see that all files have indeed been deleted, meaning that we successfully triggered the Reset functionality without having admin access or any credentials.

# Bypassing security filters

### Scenario
We have a web application which simulate a "File Manager" in which we can add new files by typing their names and hitting enter.
However, **suppose we try to delete all files by clicking on the red Reset button (in the GUI there is a red button "Reset" which seems to purge all the files in the filesystem)**.

In the File Manager web application, if we try to create a new file name with special characters in its name (e.g. test;), we get the following message:
- "Malicious Request Denied"

**This message shows that the web application uses certain filters on the back-end to identify injection attempts and then blocks any malicious requests**. No matter what we try, the web application properly blocks our requests and is secured against injection attempts. However, we may try an HTTP Verb Tampering attack to see if we can bypass the security filter altogether.

### Exploit

To try and exploit this vulnerability, let's intercept the request in Burp Suite (Burp) and then use Change Request Method to change it to another method.


To confirm whether we bypassed the security filter, **we need to attempt exploiting the vulnerability the filter is protecting: a Command Injection vulnerability**, in this case.

So, we can inject a command that creates two files and then check whether both files were created. To do so, we will use the following file name in our attack:
- (file1; touch file2;)

Then, we can once again change the request method to a GET request.

**This shows that we successfully bypassed the filter through an HTTP Verb Tampering vulnerability and achieved command injection**.

# Verb tempering prevention, insecure configurations

The following is an example of a vulnerable configuration for an Apache web server, which is located in the site configuration file (e.g. 000-default.conf), or in a .htaccess web page configuration file:

```xml
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <Limit GET>
        Require valid-user
    </Limit>
</Directory>
```

As we can see, this configuration is setting the authorization configurations for the admin web directory. However, as the ```<Limit GET>``` keyword is being used, the Require valid-user setting will only apply to GET requests, leaving the page accessible through POST requests. Even if both GET and POST were specified, this would leave the page accessible through other methods, like HEAD or OPTIONS.

The following example shows the same vulnerability for a Tomcat web server configuration, which can be found in the web.xml file for a certain Java web application:

```xml
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <http-method>GET</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```

We can see that the authorization is being limited only to the GET method with http-method, which leaves the page accessible through other HTTP methods.

Finally, the following is an example for an ASP.NET configuration found in the web.config file of a web application:

```xml
<system.web>
    <authorization>
        <allow verbs="GET" roles="admin">
            <deny verbs="GET" users="*">
        </deny>
        </allow>
    </authorization>
</system.web>
```

Once again, the allow and deny scope is limited to the GET method, which leaves the web application accessible through other HTTP methods.

The above examples show that it is not secure to limit the authorization configuration to a specific HTTP verb. This is why we should always avoid restricting authorization to a particular HTTP method and always allow/deny all HTTP verbs and methods.

If we want to specify a single method, we can use safe keywords, like LimitExcept in Apache, http-method-omission in Tomcat, and add/remove in ASP.NET, which cover all verbs except the specified ones.

Finally, to avoid similar attacks, we should generally consider disabling/denying all HEAD requests unless specifically required by the web application.


# Verb tempering prevention, insecure coding

While identifying and patching insecure web server configurations is relatively easy, doing the same for insecure code is much more challenging. This is because to identify this vulnerability in the code, we need to find inconsistencies in the use of HTTP parameters across functions, as in some instances, this may lead to unprotected functionalities and filters.

Let's consider the following PHP code from our File Manager exercise:

```php
if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9. _-]/', $_POST['filename'])) {
        system("touch " . $_REQUEST['filename']);
    } else {
        echo "Malicious Request Denied!";
    }
}
```

**If we were only considering Command Injection vulnerabilities, we would say that this is securely coded**.
The preg_match function properly looks for unwanted special characters and does not allow the input to go into the command if any special characters are found. However, the fatal error made in this case is not due to Command Injections but due to the inconsistent use of HTTP methods.

We see that the preg_match filter only checks for special characters in POST parameters with ```$_POST['filename']```. However, the final system command uses the ```$_REQUEST['filename']``` variable, which covers both GET and POST parameters. So, in the previous section, when we were sending our malicious input through a GET request, it did not get stopped by the preg_match function, as the POST parameters were empty and hence did not contain any special characters. Once we reach the system function, however, it used any parameters found in the request, and our GET parameters were used in the command, eventually leading to Command Injection.

To avoid HTTP Verb Tampering vulnerabilities in our code, we must be consistent with our use of HTTP methods and ensure that the same method is always used for any specific functionality across the web application.