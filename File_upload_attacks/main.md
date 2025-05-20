# Absent validation

The most basic type of file upload vulnerability occurs when the web application does not have any form of validation filters on the uploaded files, allowing the upload of any file type by default.

### Identifyng web framework

We need to upload a malicious script to test whether we can upload any file type to the back-end server and test whether we can use this to exploit the back-end server. Many kinds of scripts can help us exploit web applications through arbitrary file upload, most commonly a **Web Shell script and a Reverse Shell script**.

A Web Shell provides us with an easy method to interact with the back-end server by accepting shell commands and printing their output back to us within the web browser. **A web shell has to be written in the same programming language that runs the web server**, as it runs platform-specific functions and commands to execute system commands on the back-end server, making web shells non-cross-platform scripts. So, the first step would be to identify what language runs the web application.

This is usually relatively simple, as **we can often see the web page extension in the URLs, which may reveal the programming language that runs the web application**. However, in certain web frameworks and web languages, **Web Routes** are used to map URLs to web pages, in which case the web page extension may not be shown.

One easy method to determine what language runs the web application is to **visit the /index.ext page**, where we would swap out ext with various common web extensions, like php, asp, aspx, among others, to see whether any of them exist. We do not need to do this manually, of course, as we can use a tool like Burp Intruder for fuzzing the file extension using a Web Extensions wordlist, as we will see in upcoming sections.

Several other techniques may help identify the technologies running the web application, like using the **Wappalyzer extension**, which is available for all major browsers. Once added to our browser, we can click its icon to view all technologies running the web application.

### Vulnerability identification and exploiting

Now we need to upload a script in the language identified before (eg. PHP). If the file is uploaded correctly we are in.

Next step is to write a **web shell or a reverse shell** to exploit the server.

# Client-side validation

Many web applications only rely on front-end JavaScript code to validate the selected file format before it is uploaded and would not upload it if the file is not in the required format (e.g., not an image).

**However, as the file format validation is happening on the client-side, we can easily bypass it by directly interacting with the server, skipping the front-end validations altogether. We may also modify the front-end code through our browser's dev tools to disable any validation in place**.

### Back-end request modification

We can capture the upload request with Burp.

Tipically, for images, a request of type **multipart/form-data** is done. Inside the body of the request we can write our PHP shell and we can modify for example the name of the image in "something.php".

### Disabling front-end validation

Another method to bypass client-side validations is through manipulating the front-end code. As these functions are being completely processed within our web browser, we have complete control over them. So, we can modify these scripts or disable them entirely.
Tipically, this is done **using the page inspector** of the browser. We need to identify the JS code or the HTML control that not allow certain type of files.

# Blacklist filters

A blacklist code is something like this:

```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');

if (in_array($extension, $blacklist)) {
    echo "File type not allowed";
    die();
}
```

This validation method is limited. Not all PHP extensions are included so an attacker can upload a PHP file with another PHP compatible extensions and can be able to execute the script.

### Fuzzing extensions

As the web application seems to be testing the file extension, our first step is to fuzz the upload functionality with a list of potential extensions and see which of them return the error message.
We can do this using **Burp Intruder** using as wordlist a list of PHP extensions.
Example, we could find that .phtml extension works.

# Whitelist filters

A whitelist is generally more secure than a blacklist. The web server would only allow the specified extensions, and the list would not need to be comprehensive in covering uncommon extensions.
Still, there are different use cases for a blacklist and for a whitelist. A blacklist may be helpful in cases where the upload functionality needs to allow a wide variety of file types (e.g., File Manager), while a whitelist is usually only used with upload functionalities where only a few file types are allowed. Both may also be used in tandem.

An example of whitelist code is the following:
```php
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

We see that the script uses a Regular Expression (regex) to test whether the filename contains any whitelisted image extensions. The issue here lies within the regex, as it only checks whether the file name contains the extension and not if it actually ends with it.

### Double extensions

The code only tests whether the file name contains an image extension; a straightforward method of passing the regex test is through Double Extensions. For example, if the .jpg extension was allowed, we can add it in our uploaded file name and still end our filename with .php (**e.g. shell.jpg.php**), in which case we should be able to pass the whitelist test, while still uploading a PHP script that can execute PHP code.


### Reverse double extension

An example of vulnerable configuration in the server Apache:
```xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```
The above configuration is how the web server determines which files to allow PHP code execution. It specifies a whitelist with a regex pattern that matches .phar, .php, and .phtml. However, this regex pattern can have the same mistake we saw earlier if we forget to end it with ($). In such cases, any file that contains the above extensions will be allowed PHP code execution, even if it does not end with the PHP extension.


### Characters injection

Finally, let's discuss another method of bypassing a whitelist validation test through Character Injection. We can inject several characters before or after the final extension to cause the web application to misinterpret the filename and execute the uploaded file as a PHP script.
The following are some of the characters we may try injecting:
- %20
- %0a
- %00
- %0d0a
- /
- .\
- .
- …
- :

Each character has a specific use case that may trick the web application to misinterpret the file extension. For example, **shell.php%00.jpg** works with PHP servers with version 5.X or earlier, as it causes the PHP web server to end the file name after the (%00), and store it as (shell.php), while still passing the whitelist.

# Type filters

Modern web servers and web applications also test the content of the uploaded file to ensure it matches the specified type. While extension filters may accept several extensions, content filters usually specify a single category (e.g., images, videos, documents), which is why they do not typically use blacklists or whitelists. This is because web servers provide functions to check for the file content type, and it usually falls under a specific category.
There are two common methods for validating the file content: **Content-Type Header** or **File Content**. Let's see how we can identify each filter and how to bypass both of them.

### Content-type

The following is an example of how a PHP web application tests the Content-Type header to validate the file type:
```php
$type = $_FILES['uploadFile']['type'];

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```
The code sets the ($type) variable from the uploaded file's Content-Type header. Our browsers automatically set the Content-Type header when selecting a file through the file selector dialog, usually derived from the file extension. **However, since our browsers set this, this operation is a client-side operation, and we can manipulate it to change the perceived file type and potentially bypass the type filter**.

So we can intercept the request with Burp and then modify the "Content-Type" header.

### MIME-Type

The second and more common type of file content validation is testing the uploaded file's MIME-Type. **Multipurpose Internet Mail Extensions (MIME) is an internet standard that determines the type of a file through its general format and bytes structure**.

This is usually done by inspecting the first few bytes of the file's content, which contain the **File Signature or Magic Bytes**.

The following example shows how a PHP web application can test the MIME type of an uploaded file:

```php
$type = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

As we can see, the MIME types are similar to the ones found in the Content-Type headers, but their source is different, as PHP uses the mime_content_type() function to get a file's MIME type.

# What to do in case of limited file uploads

Certain file types, like **SVG, HTML, XML**, and even some image and document files, may allow us to introduce new vulnerabilities to the web application by uploading malicious versions of these files.

### XSS

Many file types may allow us to introduce a **Stored XSS vulnerability** to the web application by uploading maliciously crafted versions of them.
The most basic example is when a web application allows us to upload HTML files. Although HTML files won't allow us to execute code (e.g., PHP), it would still be possible to implement JavaScript code within them to carry an XSS or CSRF attack on whoever visits the uploaded HTML page. If the target sees a link from a website they trust, and the website is vulnerable to uploading HTML documents, it may be possible to trick them into visiting the link and carry the attack on their machines. 

**XSS attacks can also be carried with SVG images**, along with several other attacks. Scalable Vector Graphics (SVG) images are XML-based, and they describe 2D vector graphics, which the browser renders into an image. For this reason, we can modify their XML data to include an XSS payload.

For example:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```
Once we upload the image to the web application, the XSS payload will be triggered whenever the image is displayed.

### XXE

Similar attacks can be carried to lead to XXE exploitation. **With SVG images, we can also include malicious XML data to leak the source code of the web application**.
The following example can be used for an SVG image that leaks the content of (/etc/passwd):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```
Once the above SVG image is uploaded and viewed, the XML document would get processed, and we should get the info of (/etc/passwd) printed on the page or shown in the page source.

While reading systems files like /etc/passwd can be very useful for server enumeration, it can have an even more significant benefit for web penetration testing, as it allows us to read the web application's source files. **Access to the source code will enable us to find more vulnerabilities to exploit within the web application through Whitebox Penetration Testing**.

To use XXE to read source code in PHP web applications, we can use the following payload in our SVG image:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```
Once the SVG image is displayed, we should get the base64 encoded content of index.php, which we can decode to read the source code.

# Injections in file name

A common file upload attack uses a malicious string for the uploaded file name, which may get executed or processed if the uploaded file name is displayed (i.e., reflected) on the page. **We can try injecting a command in the file name, and if the web application uses the file name within an OS command, it may lead to a command injection attack**.
For example, if we name a file file$(whoami).jpg or file whoami.jpg or file.jpg||whoami, and then the web application attempts to move the uploaded file with an OS command (e.g. mv file /tmp), then our file name would inject the whoami command, which would get executed, leading to remote code execution.

# Upload directory disclosure

In some file upload forms, like a feedback form or a submission form, we may not have access to the link of our uploaded file and may not know the uploads directory. In such cases, we may utilize fuzzing to look for the uploads directory or even use other vulnerabilities (e.g., LFI/XXE) to find where the uploaded files are by reading the web applications source code, as we saw in the previous section.
Another method we can use to disclose the uploads directory is through forcing error messages, as they often reveal helpful information for further exploitation. One attack we can use to cause such errors is uploading a file with a name that already exists or sending two identical requests simultaneously. This may lead the web server to show an error that it could not write the file, which may disclose the uploads directory.

# Windows specific attacks

One such attack is using reserved characters, **such as (|, <, >, *, or ?)**, which are usually reserved for special uses like wildcards. If the web application does not properly sanitize these names or wrap them within quotes, they may refer to another file (which may not exist) and cause an error that discloses the upload directory. Similarly, we may use Windows reserved names for the uploaded file name, like **(CON, COM1, LPT1, or NUL)**, which may also cause an error as the web application will not be allowed to write a file with this name.

Finally, we may utilize the Windows 8.3 Filename Convention to overwrite existing files or refer to files that do not exist. Older versions of Windows were limited to a short length for file names, so they used a Tilde character (~) to complete the file name, which we can use to our advantage.