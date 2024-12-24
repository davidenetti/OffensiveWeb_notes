A Brute Force attack is a method of attempting to guess passwords or keys by automated probing. An example of a brute-force attack is password cracking. Passwords are usually not stored in clear text on the systems but as hash values.

Here is a small list of files that can contain hashed passwords:
- unattend.xml (Windows);
- sysprep.inf (Windows);
- SAM (Windows);
- shadow (Linux);
- shadow.bak (Linux);
- password (Linux).

Since the password cannot be calculated backward from the hash value, the brute force method determines the hash values belonging to the randomly selected passwords until a hash value matches the stored hash value. In this case, the password is found. **This method is also called offline brute-forcing**.

On most websites, there is always a login area for administrators, authors, and users somewhere. Furthermore, usernames are often recognizable on the web pages, and complex passwords are rarely used because they are difficult to remember. **Therefore it is worth using the online brute forcing method after a proper enumeration if we could not identify any initial foothold**.


### Scenario

We found an unusual host on the network during our black box penetration test and had a closer look at it. We discovered a web server on it that is running on a non-standard port. Many web servers or individual contents on the web servers are still often used with the Basic HTTP AUTH scheme. Like in our case, we found such a webserver with such a path, which should arouse some curiosity. The HTTP specification provides two parallel authentication mechanisms:
- Basic HTTP AUTH is used to authenticate the user to the HTTP server;
- Proxy Server Authentication is used to authenticate the user to an intermediate proxy server.

These two mechanisms work very similarly as they use requests, response status codes, and response headers. However, there are differences in the status codes and header names used.

The Basic HTTP Authentication scheme uses user ID and password for authentication. The client sends a request without authentication information with its first request. The server's response contains the WWW-Authenticate header field, which requests the client to provide the credentials. This header field also defines details of how the authentication has to take place. **The client is asked to submit the authentication information. In its response, the server transmits the so-called realm, a character string that tells the client who is requesting the data**.
**The client uses the Base64 method for encoding the identifier and password. This encoded character string is transmitted to the server in the Authorization header field**.



There are several types of password attacks, such as:

- Dictionary attack;
- Brute force;
- Traffic interception;
- Man In the Middle;
- Key Logging;
- Social engineering.

# Brute force attack

A Brute Force Attack does not depend on a wordlist of common passwords, but it works by trying all possible character combinations for the length we specified. For example, if we specify the password's length as 4, it would test all keys from aaaa to zzzz, literally brute forcing all characters to find a working password.

However, even if we only use lowercase English characters, this would have almost half a million permutations -26x26x26x26 = 456,976-, which is a huge number, even though we only have a password length of 4.

**Once the password length starts to increase, and we start testing for mixed casings, numbers, and special characters, the time it would take to brute force, these passwords can take millions of years**.

All of this shows that relying completely on brute force attacks is not ideal, and this is especially true for brute-forcing attacks that take place over the network, like in hydra.

# Dictionary attack

A Dictionary Attack tries to guess passwords with the help of lists. **The goal is to use a list of known passwords to guess an unknown password**. This method is useful whenever it can be assumed that passwords with reasonable character combinations are used.

There are many methodologies to carry a Login Brute Force attacks:

- **Online Brute Force Attack**: Attacking a live application over the network, like HTTP, - HTTPs, SSH, FTP, and others;
- **Offline Brute Force Attack**: Also known as Offline Password Cracking, where you attempt to - crack a hash of an encrypted password;
- **Reverse Brute Force Attack**: Also known as username brute-forcing, where you try a single - common password with a list of usernames on a certain service;
- **Hybrid Brute Force Attack**: Attacking a user by creating a customized password wordlist, built using known intelligence about the user or the service.

# Hydra

Hydra is a handy tool for Login Brute Forcing, as it covers a wide variety of attacks and services and is relatively fast compared to the others. It can test any pair of credentials and verify whether they are successful or not but in huge numbers and a very quick manner.

As we don't know which user to brute force, we will have to brute force both fields. We can either provide different wordlists for the usernames and passwords and iterate over all possible username and password combinations. However, we should keep this as a last resort.

It is very common to find pairs of usernames and passwords used together, especially when default service passwords are kept unchanged. That is why it is better to always start with a wordlist of such credential pairs -e.g. test:test-, and scan all of them first.

Example of Hydra command:
```bash
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 178.211.23.155 -s 31099 http-get /
```

### Username/password attack in Hydra

Hydra requires at least 3 specific flags if the credentials are in one single list to perform a brute force attack against a web service:

- Credentials
- Target Host
- Target Path

Credentials can also be separated by usernames and passwords. We can use the **-L flag for the usernames wordlist and the -P flag for the passwords wordlist**. Since we don't want to brute force all the usernames in combination with the passwords in the lists, we can tell hydra to **stop after the first successful login by specifying the flag -f**.



Tip: We will add the **"-u" flag**, so that it tries all users on each password, instead of trying all 14 million passwords on one user, before moving on to the next.

Example of command:

```bash
hydra -L /opt/useful/SecLists/Usernames/Names/names.txt -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -u -f 178.35.49.134 -s 32901 http-get /
```


If we were to **only brute force the username or password**, we could assign a static username or password with the same flag but lowercase. For example, we can brute force passwords for the test user by adding -l test, and then adding a password word list with -P rockyou.txt.

### Hydra modules

Hydra provides many different types of requests we can use to brute force different services. If we use hydra -h, we should be able to list supported services:

Two interesting modules:
1. http[s]-{head|get|post}
2. http[s]-post-form

The 1st module serves for basic HTTP authentication, while the 2nd module is used for login forms, like .php or .aspx and others. 
To decide which module we need, we have to determine whether the web application uses GET or a POST form. We can test it by trying to log in and pay attention to the URL. If we recognize that any of our input was pasted into the URL, the web application uses a GET form. Otherwise, it uses a POST form.

Typically for a **http-post-form module** we need to provide three parameters:

1. URL path, which holds the login form;
2. POST parameters for username/password;
3. A failed/success login string, which lets hydra recognize whether the login attempt was successful or not.

The second parameter is the POST parameters for username/passwords:

- ```/login.php:[user parameter]=^USER^&[password parameter]=^PASS^```

The third parameter is a failed/successful login attempt string:
- ```/login.php:[user parameter]=^USER^&[password parameter]=^PASS^:[FAIL/SUCCESS]=[success/failed string]```

To make it possible for hydra to distinguish between successfully submitted credentials and failed attempts, we have to specify a unique string from the source code of the page we're using to log in. Hydra will examine the HTML code of the response page it gets after each attempt, looking for the string we provided.

We can specify two different types of analysis that act as a Boolean value:
- Fail: F=html_content;
- Success: S=html_content.

If we provide a fail string, it will keep looking until the string is not found in the response. Another way is if we provide a success string, it will keep looking until the string is found in the response.

If we need something unique to provide as failure or success string, **we can use a whole HTML tag and its content**.

### Using browser's developer tools to intercept login parameters

Tipically inside the "network tab" we can copy the POST data. Tipically this provide us with something like: "username=test&password=test".

Another option is to use "**copy as cURL**".

### Using Burp to intercept login parameters

We can also intercept the login POST with Burp.


### Default credentials

Let's try to use the ftp-betterdefaultpasslist.txt list with the default credentials to test if one of the accounts is registered in the web application:

```bash
hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 178.35.49.134 -s 32901 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```

Or something like this:
```bash
hydra -l admin -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -f 178.35.49.134 -s 32901 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```


# Personalized wordlists

To create a personalized wordlist for the user, we will need to collect some information about them. As our example here is a known public figure, we can check out their Wikipedia page or do a basic Google search to gather the necessary information. Even if this was not a known figure, we can still carry out the same attack and create a personalized wordlist for them. All we need to do is gather some information about them.

### CUPP

Cupp is very easy to use. We run it in interactive mode by specifying the -i argument, and answer the questions.

WE can specify, also, **the password policy** if we know it. In this manner, we can generate only passwords which are compliant to the password policy.

We can do something like this:

```bash
sed -ri '/^.{,7}$/d' william.txt            # remove shorter than 8
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # remove no special chars
sed -ri '/[0-9]+/!d' william.txt            # remove no numbers

sed -ri '/[A-Z]/!d'                         # Remove all the strings in the file which not
                                            # contains at least one upper character
```

### Mangling

It is still possible to create many permutations of each word in that list. We never know how our target thinks when creating their password, and so our safest option is to add as many alterations and permutations as possible, noting that this will, of course, take much more time to brute force.

Many great tools do word mangling and case permutation quickly and easily, like **rsmangler** or **The Mentalist**.


# Personalized usernames 

We should also consider creating a personalized username wordlist based on the person's available details.
There are several methods to create the list of potential usernames, the most basic of which is simply writing it manually.

One such tool we can use is **Username Anarchy**.

# SSH attack

The command used to attack a login service is fairly straightforward. We simply have to provide the username/password wordlists, and add service://SERVER_IP:PORT at the end. As usual, we will add the -u -f flags. Finally, when we run the command for the first time, hydra will suggest that we add the -t 4 flag for a max number of parallel attempts, as many SSH limit the number of parallel connections and drop other connections, resulting in many of our attempts being dropped. Our final command should be as follows:

```bash
hydra -L bill.txt -P william.txt -u -f ssh://178.35.49.134:22 -t 4
```

# FTP brute forcing

So, similarly to how we attacked the SSH service, we can perform a similar attack on FTP:

```bash
hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1
```

