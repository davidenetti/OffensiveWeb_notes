Authentication is defined as "The process of verifying a claim that a system entity or system resource has a certain attribute value" in RFC 4949. In information security, authentication is the process of confirming an entity's identity, ensuring they are who they claim to be. On the other hand, authorization is an "approval that is granted to a system entity to access a system resource".

The most widespread authentication method in web applications is login forms, where users enter their username and password to prove their identity.

Information technology systems can implement different authentication methods. Typically, they can be divided into the following three major categories:

- Knowledge-based authentication
- Ownership-based authentication
- Inherence-based authentication

### Knowledge
Authentication based on knowledge factors relies on something that the user knows to prove their identity. The user provides information such as passwords, passphrases, PINs, or answers to security questions.

### Ownership
Authentication based on ownership factors relies on something the user possesses. The user proves their identity by proving the ownership of a physical object or device, such as ID cards, security tokens, or smartphones with authentication apps. 

### Inherence
Lastly, authentication based on inherence factors relies on something the user is or does. This includes biometric factors such as fingerprints, facial patterns, and voice recognition, or signatures. Biometric authentication is highly effective since biometric traits are inherently tied to an individual user.

### Single-Factor Authentication vs Multi-Factor Authentication

Single-factor authentication relies solely on a single methods. For instance, password authentication solely relies on knowledge of the password. As such, it is a single-factor authentication method.

On the other hand, multi-factor authentication (MFA) involves multiple authentication methods. For instance, if a web application requires a password and a time-based one-time password (TOTP), it relies on knowledge of the password and ownership of the TOTP device for authentication. In the particular case when exactly two factors are required, MFA is commonly referred to as 2-factor authentication (2FA).

# User enumeration

User enumeration vulnerabilities arise when a web application responds differently to registered/valid and invalid inputs for authentication endpoints. User enumeration vulnerabilities frequently occur in functions based on the user's username, such as user login, user registration, and password reset.

Protection against username enumeration attacks can have an impact on user experience. A web application revealing whether a username exists may help a legitimate user identify that they failed to type their username correctly. Still, the same applies to an attacker trying to determine valid usernames. Even well-known and mature applications, like WordPress, allow for user enumeration by default.
On the other hand, a valid username results in a different error message.

To obtain a list of valid users, an attacker typically requires a wordlist of usernames to test. Usernames are often far less complicated than passwords. They rarely contain special characters when they are not email addresses. A list of common users allows an attacker to narrow the scope of a brute-force attack or carry out targeted attacks (leveraging OSINT) against support employees or users. Also, a common password could be easily sprayed against valid accounts, often leading to a successful account compromise. Further ways of harvesting usernames are crawling a web application or using public information, such as company profiles on social networks. A good starting point is the wordlist collection SecLists. 

```bash
ffuf -w /opt/useful/SecLists/Usernames/xato-net-10-million-usernames.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=invalid" -fr "Unknown user"
```

Let us exploit this difference in error messages returned and use SecLists's wordlist xato-net-10-million-usernames.txt to enumerate valid users with ffuf. We can specify the wordlist with the -w parameter, the POST data with the -d parameter, and the keyword FUZZ in the username to fuzz valid users. Finally, we can filter out invalid users by removing responses containing the string Unknown user.

### User enumeration via side-channel attacks

While differences in the web application's response are the simplest and most obvious way to enumerate valid usernames, we might also be able to enumerate valid usernames via side channels. Side-channel attacks do not directly target the web application's response but rather extra information that can be obtained or inferred from the response. An example of a side channel is the response timing, i.e., the time it takes for the web application's response to reach us. Suppose a web application does database lookups only for valid usernames. In that case, we might be able to measure a difference in the response time and enumerate valid usernames this way, even if the response is the same.

# Brute forcing password

After successfully identifying valid users, password-based authentication relies on the password as a sole measure for authenticating the user. Since users tend to select an easy-to-remember password, attackers may be able to guess or brute-force it.

Brute forcing password using ffuf:
```bash
ffuf -w ./custom_wordlist.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=FUZZ" -fr "Invalid username"
```

# Brute-Forcing Password Reset Tokens
Many web applications implement a password-recovery functionality if a user forgets their password. This password-recovery functionality typically relies on a one-time reset token, which is transmitted to the user, for instance, via SMS or E-Mail. The user can then authenticate using this token, enabling them to reset their password and access their account.

As such, a weak password-reset token may be brute-forced or predicted by an attacker to take over a victim's account.

To identify weak reset tokens, we typically need to create an account on the target web application, request a password reset token, and then analyze it. In this example, let us assume we have received the following password reset e-mail:

```
Hello,

We have received a request to reset the password associated with your account. To proceed with resetting your password, please follow the instructions below:

1. Click on the following link to reset your password: Click

2. If the above link doesn't work, copy and paste the following URL into your web browser: http://weak_reset.htb/reset_password.php?token=7351

Please note that this link will expire in 24 hours, so please complete the password reset process as soon as possible. If you did not request a password reset, please disregard this e-mail.

Thank you.
```

As we can see, the password reset link contains the reset token in the GET-parameter token. In this example, the token is 7351. Given that the token consists of only a 4-digit number, there can be only 10,000 possible values. This allows us to hijack users' accounts by requesting a password reset and then brute-forcing the token.

We will use ffuf to brute-force all possible reset tokens. First, we need to create a wordlist of all possible tokens from 0000 to 9999, which we can achieve with seq:

```bash
seq -w 0 9999 > tokens.txt
```

The **-w flag pads all numbers to the same length by prepending zeroes**, which we can verify by looking at the first few lines of the output file.

```bash
ffuf -w ./tokens.txt -u http://weak_reset.htb/reset_password.php?token=FUZZ -fr "The provided token is invalid"
```
By specifying the reset token in the GET-parameter token in the /reset_password.php endpoint, we can reset the password of the corresponding account, enabling us to take over the account.

# Brute-Forcing 2FA Codes
Two-factor authentication (2FA) provides an additional layer of security to protect user accounts from unauthorized access. Typically, this is achieved by combining knowledge-based authentication (password) with ownership-based authentication (the 2FA device). However, 2FA can also be achieved by combining any other two of the major three authentication categories we discussed previously. Therefore, 2FA makes it significantly more difficult for attackers to access an account even if they manage to obtain the user's credentials. By requiring users to provide a second form of authentication, such as a one-time code generated by an authenticator app or sent via SMS, 2FA mitigates the risk of unauthorized access. This extra layer of security significantly enhances the overall security posture of an account, reducing the likelihood of successful account breaches.

**One of the most common 2FA implementations relies on the user's password and a time-based one-time password (TOTP) provided to the user's smartphone by an authenticator app or via SMS. These TOTPs typically consist only of digits, making them potentially guessable if the length is insufficient and the web application does not implement measures against successive submission of incorrect TOTPs**.

We need to:
- Intercept the request with Burp to identify the POST parameter in which the OTP is sent;
- Brute force the OTP codes with FFUF for example;
- Furthermore, we need to specify our session token in the PHPSESSID cookie to associate the TOTP with our authenticated session.

```bash
ffuf -w ./tokens.txt -u http://bf_2fa.htb/2fa.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=fpfcm5b8dh1ibfa7idg0he7l93" -d "otp=FUZZ" -fr "Invalid 2FA Code"
```

# Weak brute force protection

The best mechanism are:
- Rate limits: Its primary purpose is to prevent servers from being overwhelmed by too many requests at once, prevent system downtime, and prevent brute-force attacksMany rate limit implementation rely on the IP address to identify the attacker. However, in a real-world scenario, obtaining the attacker's IP address might not always be as simple as it seems. For instance, if there are middleboxes such as reverse proxies, load balancers, or web caches, a request's source IP address will belong to the middlebox, not the attacker. Thus, some rate limits rely on HTTP headers such as X-Forwarded-For to obtain the actual source IP address. However, this causes an issue as an attacker can set arbitrary HTTP headers in request, bypassing the rate limit entirely. This enables an attacker to conduct a brute-force attack by randomizing the X-Forwarded-For header in each HTTP request to avoid the rate limit. Vulnerabilities like this occur frequently in the real world, for instance, as reported in CVE-2020-35590;
- CAPTCHAs: A Completely Automated Public Turing test to tell Computers and Humans Apart (CAPTCHA) is a security measure to prevent bots from submitting requests. By forcing humans to make requests instead of bots or scripts, brute-force attacks become a manual task, making them infeasible in most cases. CAPTCHAs typically present challenges that are easy for humans to solve but difficult for bots, such as identifying distorted text, selecting particular objects from images, or solving simple puzzles. By requiring users to complete these challenges before accessing certain features or submitting forms, CAPTCHAs help prevent automated scripts from performing actions that could be harmful, such as spamming forums, creating fake accounts, or launching brute-force attacks on login pages. While CAPTCHAs serve an essential purpose in deterring automated abuse, they can also present usability challenges for some users, particularly those with visual impairments or specific cognitive disabilities.

# Default credentials

Many platforms provide lists of default credentials for a wide variety of web applications. Such an example is the web database maintained by **CIRT.net**. For instance, if we identified a Cisco device during a penetration test, we can search the database for default credentials for Cisco devices.

Other resources:
- https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials;
- https://github.com/scadastrangelove/SCADAPASS/tree/master.

# Guessable password reset questions

Often, web applications authenticate users who have lost their passwords by requesting that they answer one or multiple security questions. During registration, users provide answers to predefined and generic security questions, disallowing users from entering custom ones. **Therefore, within the same web application, the security questions of all users will be the same, allowing attackers to abuse them**.

For instance, assuming a web application uses a security question like "What city were you born in?".

**We can attempt to brute-force the answer to this question by using a proper wordlist. There are multiple lists containing large cities in the world**.

Tipically we need to **intercept the request with Burp and identify the POST parameter which contains the answer to the security question.
Then **with FFUF we can brute force this field**:
```bash
ffuf -w ./city_wordlist.txt -u http://pwreset.htb/security_question.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=39b54j201u3rhu4tab1pvdb4pv" -d "security_response=FUZZ" -fr "Incorrect response."
```

# Manipulating the Reset Request

Another instance of a flawed password reset logic occurs when a user can manipulate a potentially hidden parameter to reset the password of a different account.
Another instance of a flawed password reset logic occurs when a user can manipulate a potentially hidden parameter to reset the password of a different account.

For instance, consider the following password reset flow, which is similar to the one discussed above. First, we specify the username:

```http
POST /reset.php HTTP/1.1
Host: pwreset.htb
Content-Length: 18
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=39b54j201u3rhu4tab1pvdb4pv

username=htb-stdnt
```

Afterward, we need to supply the response to the security question. Supplying the security response London results in the following request:

```http
POST /security_question.php HTTP/1.1
Host: pwreset.htb
Content-Length: 43
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=39b54j201u3rhu4tab1pvdb4pv

security_response=London&username=htb-stdnt
```

**As we can see, the username is contained in the form as a hidden parameter and sent along with the security response**.

The final request looks like this (the password reset one):

```http
POST /reset_password.php HTTP/1.1
Host: pwreset.htb
Content-Length: 36
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=39b54j201u3rhu4tab1pvdb4pv

password=P@$$w0rd&username=htb-stdnt
```

Suppose the web application does not properly verify that the usernames in both requests match. In that case, we can skip the security question or supply the answer to our security question and then set the password of an entirely different account. For instance, we can change the admin user's password by manipulating the username parameter of the password reset request:

```http
POST /reset_password.php HTTP/1.1
Host: pwreset.htb
Content-Length: 32
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=39b54j201u3rhu4tab1pvdb4pv

password=P@$$w0rd&username=admin
```
**To prevent this vulnerability, keeping a consistent state during the entire password reset process is essential**.


# Authentication bypass via direct access

The most straightforward way of bypassing authentication checks is to request the protected resource directly from an unauthenticated context. An unauthenticated attacker can access protected information if the web application does not properly verify that the request is authenticated.

For instance, let us assume that we know that the web application redirects users to the /admin.php endpoint after successful authentication, providing protected information only to authenticated users. If the web application relies solely on the login page to authenticate users, we can access the protected resource directly by accessing the /admin.php endpoint.

While this scenario is uncommon in the real world, a slight variant occasionally happens in vulnerable web applications.

To illustrate the vulnerability, let us assume a web application uses the following snippet of PHP code to verify whether a user is authenticated:

```php
if(!$_SESSION['active']) {
	header("Location: index.php");
}
```

This code **redirects the user to /index.php if the session is not active**, i.e., if the user is not authenticated. However, **the PHP script does not stop execution**, resulting in protected information within the page being sent in the response body.

We can easily trick the browser into displaying the admin page by intercepting the response and changing the status code from 302 to 200. To do this:
- Enable Intercept in Burp;
- Browse to the /admin.php endpoint in the web browser;
- Right-click on the request and select Do intercept > Response to this request to intercept the response;
- Forward the request by clicking on Forward. Since we intercepted the response, we can now edit it. To force the browser to display the content, we need to change the status code from 302 Found to 200 OK.

To prevent the protected information from being returned in the body of the redirect response, the PHP script needs to exit after issuing the redirect:

```php
if(!$_SESSION['active']) {
	header("Location: index.php");
	exit;
}
```

# Authentication bypass via parameters modification

This type of vulnerability is closely related to authorization issues such as **Insecure Direct Object Reference (IDOR) vulnerabilities**.

Let us take a look at our target web application. This time, we are provided with credentials for the user **htb-stdnt**. After logging in, we are redirected to **/admin.php?user_id=183**.

To investigate the purpose of the user_id parameter, let us remove it from our request to /admin.php. When doing so, we are redirected back to the login screen at /index.php, even though our session provided in the PHPSESSID cookie is still valid.
Thus, we can assume that the parameter user_id is related to authentication. We can bypass authentication entirely by accessing the URL /admin.php?user_id=183 directly.
**Based on the parameter name user_id, we can infer that the parameter specifies the ID of the user accessing the page. If we can guess or brute-force the user ID of an administrator, we might be able to access the page with administrative privileges, thus revealing the admin information**.

# Attacking session tokens

So far, we have focused on abusing flawed implementations of web applications authentication. However, vulnerabilities related to authentication can arise not only from the implementation of the authentication itself but also from the handling of session tokens. **Session tokens are unique identifiers a web application uses to identify a user. More specifically, the session token is tied to the user's session. If an attacker can obtain a valid session token of another user, the attacker can impersonate the user to the web application, thus taking over their session**.


### Brute force attacks to session tokens

Suppose a session token does not provide sufficient randomness and is cryptographically weak. In that case, we can brute-force valid session tokens similarly to how we were able to brute-force valid password-reset tokens.
**This can happen if a session token is too short or contains static data that does not provide randomness to the token, i.e., the token provides insufficient entropy**.

**Example**: a session token which is a 4 chars length string. This scenario is relatively uncommon in the real world. In a slightly more common variant, the session token itself provides sufficient length; however, the token consists of hardcoded prepended and appended values, while only a small part of the session token is dynamic to provide randomness.

**Another (more realistic) example**: 
The session token is 32 characters long; thus, it seems infeasible to enumerate other users' valid sessions. However, let us send the login request multiple times and take note of the session tokens assigned by the web application. This results in the following session tokens:
- 2c0c58b27c71a2ec5bf2b4b6e892b9f9
- 2c0c58b27c71a2ec5bf2b4546092b9f9
- 2c0c58b27c71a2ec5bf2b497f592b9f9
- 2c0c58b27c71a2ec5bf2b48bcf92b9f9
- 2c0c58b27c71a2ec5bf2b4735e92b9f9

As we can see, all session tokens are very similar. In fact, of the 32 characters, 28 are the same for all five captured sessions. **The session tokens consist of the static string 2c0c58b27c71a2ec5bf2b4 followed by four random characters and the static string 92b9f9**. This reduces the effective randomness of the session tokens. Since 28 out of 32 characters are static, there are only four characters we need to enumerate to brute-force all existing active sessions, enabling us to hijack all active sessions.

Another vulnerable example would be an **incrementing session identifier**. For instance, consider the following capture of successive session tokens.

### Attacking predictable session tokens

In a more realistic scenario, the session token does provide sufficient randomness on the surface. However, the generation of session tokens is not truly random; **it can be predicted by an attacker with insight into the session token generation logic**. **The simplest form of predictable session tokens contains encoded data we can tamper with**. While these session tokens might seem random at first, a simple analysis reveals that it is base64-encoded data.

Example:

```bash
echo -n dXNlcj1odGItc3RkbnQ7cm9sZT11c2Vy | base64 -d

user=htb-stdnt;role=user
```

As we can see, the cookie contains information about the user and the role tied to the session. However, there is no security measure in place that prevents us from tampering with the data. We can forge our own session token by manipulating the data and base64-encoding it to match the expected format. This enables us to forge an admin cookie:

```bash
echo -n 'user=htb-stdnt;role=admin' | base64

dXNlcj1odGItc3RkbnQ7cm9sZT1hZG1pbg==
```

Another **variant of session tokens contains the result of an encryption of a data sequence**. A weak cryptographic algorithm could lead to privilege escalation or authentication bypass, just like plain encoding. Improper handling of cryptographic algorithms or injection of user-provided data into the input of an encryption function can lead to vulnerabilities in the session token generation. However, it is often challenging to attack encryption-based session tokens in a black box approach without access to the source code responsible for session token generation.


# Session fixation

Session Fixation is an attack that enables an attacker to obtain a victim's valid session. A web application vulnerable to session fixation does not assign a new session token after a successful authentication. If an attacker can coerce the victim into using a session token chosen by the attacker, session fixation enables an attacker to steal the victim's session and access their account.

For instance, assume a web application vulnerable to session fixation uses a session token in the HTTP cookie session. Furthermore, the web application sets the user's session cookie to a value provided in the sid GET parameter. Under these circumstances, a session fixation attack could look like this:

1. An attacker obtains a valid session token by authenticating to the web application. For instance, let us assume the session token is a1b2c3d4e5f6. Afterward, the attacker invalidates their session by logging out;
2. The attacker tricks the victim to use the known session token by sending the following link: http://vulnerable.htb/?sid=a1b2c3d4e5f6. When the victim clicks this link, the web application sets the session cookie to the provided value, i.e., the response looks like this:
    ```http
    HTTP/1.1 200 OK
    [...]
    Set-Cookie: session=a1b2c3d4e5f6
    [...]
    ```
3. The victim authenticates to the vulnerable web application. The victim's browser already stores the attacker-provided session cookie, so it is sent along with the login request. The victim uses the attacker-provided session token since the web application does not assign a new one;
4. Since the attacker knows the victim's session token a1b2c3d4e5f6, they can hijack the victim's session.

A web application **must assign a new randomly generated session token after successful authentication** to prevent session fixation attacks.

# Improper Session Timeout

Lastly, a web application must define a proper Session Timeout for a session token. After the time interval defined in the session timeout has passed, the session will expire, and the session token is no longer accepted. If a web application does not define a session timeout, the session token would be valid infinitely, enabling an attacker to use a hijacked session effectively forever. For the security of a web application, the session timeout must be appropriately set. Because each web application has different business requirements, there is no universal session timeout value.

