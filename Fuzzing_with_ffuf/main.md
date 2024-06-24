The term fuzzing refers to a testing technique that sends various types of user input to a certain interface to study how it would react. If we were fuzzing for SQL injection vulnerabilities, we would be sending random special characters and seeing how the server would react. If we were fuzzing for a buffer overflow, we would be sending long strings and incrementing their length to see if and when the binary would break.

We usually utilize pre-defined wordlists of commonly used terms for each type of test for web fuzzing to see if the webserver would accept them. This is done because web servers do not usually provide a directory of all available links and domains (unless terribly configured), and so we would have to check for various links and see which ones return pages. For example, if we visit https://www.example.com/doesnotexist, we would get an HTTP code **404 Page Not Found**. However, if we visit a page that exists, like /login, we would get the login page and get an HTTP code **200 OK**.

This is the basic idea behind web fuzzing for pages and directories. Still, we cannot do this manually, as it will take forever. This is why we have tools that do this automatically, efficiently, and very quickly.

# Directory fuzzing

As we can see from the example above, the main two options are -w for wordlists and -u for the URL. We can assign a wordlist to a keyword to refer to it where we want to fuzz. For example, we can pick our wordlist and assign the keyword FUZZ to it by adding :FUZZ after it:
- **ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ**

Next, as we want to be fuzzing for web directories, we can place the FUZZ keyword where the directory would be within our URL, with:
- **ffuf -w <SNIP> -u http://SERVER_IP:PORT/FUZZ**

# Pages extension fuzzing

To find out what types of pages the website uses, like .html, .php or something else, we can put the keyword FUZZ where the extension would be using ".FUZZ" or only "FUZZ" if the "." is already in the wordlist, and using a wordlist for common extensions.
- ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ


# Pages fuzzing

Now that we know the extension used by the web app pages, we can fuzz the pages themselves (for example sssuming we have found the use of .php pages):
- ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php

# Recursive fuzzing

So far, we have been fuzzing for directories, then going under these directories, and then fuzzing for files. However, if we had dozens of directories, each with their own subdirectories and files, this would take a very long time to complete. To be able to automate this, we will utilize what is known as recursive fuzzing.

In ffuf, we can enable recursive scanning with the **-recursion** flag, and we can specify the depth with the -recursion-depth flag. If we specify **-recursion-depth 1**, it will only fuzz the main directories and their direct sub-directories. If any sub-sub-directories are identified (like /login/user, it will not fuzz them for pages). When using recursion in ffuf, we can specify our extension with **-e .php**
- **ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v**


# sub-domain fuzzing

- **ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.example.com/**

# Vhosts fuzzing

- **ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://example.com:PORT/ -H 'Host: FUZZ.example.com'**

# Filtering results in ffuf
Ffuf provides the option to match or filter out a specific HTTP code, response size, or amount of words. We can see that with.

MATCHER OPTIONS:
-mc Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403)
-ml Match amount of lines in response
-mr Match regexp
-ms Match HTTP response size
-mw Match amount of words in response

FILTER OPTIONS:
-fc Filter HTTP status codes from response. Comma separated list of codes and ranges
-fl Filter by amount of lines in response. Comma separated list of line counts and ranges
-fr Filter regexp
-fs Filter HTTP response size. Comma separated list of sizes and ranges
-fw Filter by amount of words in response. Comma separated list of word counts and ranges


# Parameter fuzzing

- **ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.example.com:PORT/admin/admin.php?FUZZ=key -fs xxx**

- **ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.example.com:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx**

# Fuzzing value in GET/POST
- **ffuf -w ids.txt:FUZZ -u http://admin.example.com:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx**
