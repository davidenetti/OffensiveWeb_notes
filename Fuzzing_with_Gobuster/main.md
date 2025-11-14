The term fuzzing refers to a testing technique that sends various types of user input to a certain interface to study how it would react. If we were fuzzing for SQL injection vulnerabilities, we would be sending random special characters and seeing how the server would react. If we were fuzzing for a buffer overflow, we would be sending long strings and incrementing their length to see if and when the binary would break.

We usually utilize pre-defined wordlists of commonly used terms for each type of test for web fuzzing to see if the webserver would accept them. This is done because web servers do not usually provide a directory of all available links and domains (unless terribly configured), and so we would have to check for various links and see which ones return pages. For example, if we visit https://www.example.com/doesnotexist, we would get an HTTP code **404 Page Not Found**. However, if we visit a page that exists, like /login, we would get the login page and get an HTTP code **200 OK**.

This is the basic idea behind web fuzzing for pages and directories. Still, we cannot do this manually, as it will take forever. This is why we have tools that do this automatically, efficiently, and very quickly.

# Directory and pages fuzzing
```bash
gobuster dir -u http://IP:PORT -w /Wordlists/common.txt -x html,php,tar.gz,txt
```

# Pages extension fuzzing
To find out what types of pages the website uses, like .html, .php or something else ywe can use the `-x html,php,tar.gz,txt` flag.

# Recursive fuzzing
So far, we have been fuzzing for directories, then going under these directories, and then fuzzing for files. However, if we had dozens of directories, each with their own subdirectories and files, this would take a very long time to complete. To be able to automate this, we will utilize what is known as recursive fuzzing. In Gobuster you can enable recursion with the `-r` option.
```
gobuster dir -u http://google.com/ -w /Wordlists/common.txt -x html,php,tar.gz,txt -r
```

# DNS subdomain fuzzing

```
gobuster dns -do example.com -w /path/to/wordlist.txt

# Use custom DNS server
gobuster dns -do example.com -w wordlist.txt -r 8.8.8.8:53

# Increase threads for faster scanning
gobuster dns -do example.com -w wordlist.txt -t 50
```



# Vhosts fuzzing (using fuzz mode)
Using **fuzz mode** we can use FUZZ keyword where we want to fuzz. Also, with the `-b` flag we filter out status code also ranges in the format `200-299`.

```
gobuster fuzz -u http://94.237.120.99:44514 -H "Host: FUZZ.fuzzing_fun.htb" -w /Wordlists/common.txt -b 400-499
```

# Filtering results in ffuf

- **--exclude-statuscodes value, -b value**: Excluded status codes. Can also handle ranges like 200,300-400,404
- **--exclude-length value, --xl value**: Exclude the following content lengths (completely ignores the status). You can separate multiple lengths by comma and it also supports ranges like 203-206


# Parameter fuzzing
```
gobuster fuzz -u http://IP:PORT/admin/panel.php?accessID=FUZZ -w /Wordlists/common.txt --exclude-length 58
```
