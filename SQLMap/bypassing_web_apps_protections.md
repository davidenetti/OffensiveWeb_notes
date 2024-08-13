# CSRF token

One of the first lines of defense against the usage of automation tools is the incorporation of anti-CSRF (i.e., Cross-Site Request Forgery) tokens into all HTTP requests, especially those generated as a result of web-form filling.In most basic terms, each HTTP request in such a scenario should have a (valid) token value available only if the user actually visited and used the page. While the original idea was the prevention of scenarios with malicious links, where just opening these links would have undesired consequences for unaware logged-in users (e.g., open administrator pages and add a new user with predefined credentials), this security feature also inadvertently hardened the applications against the (unwanted) automation.

Nevertheless, SQLMap has options that can help in bypassing anti-CSRF protection. Namely, the most important option is --csrf-token. By specifying the token parameter name (which should already be available within the provided request data), SQLMap will automatically attempt to parse the target response content and search for fresh token values so it can use them in the next request.
Additionally, even in a case where the user does not explicitly specify the token's name via --csrf-token, if one of the provided parameters contains any of the common infixes (i.e. csrf, xsrf, token), the user will be prompted whether to update it in further requests:

```bash
sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"
```

# Unique value bypass

In some cases, the web application may only require unique values to be provided inside predefined parameters. Such a mechanism is similar to the anti-CSRF technique described above, except that there is no need to parse the web page content. So, by simply ensuring that each request has a unique value for a predefined parameter, the web application can easily prevent CSRF attempts while at the same time averting some of the automation tools. For this, the option --randomize should be used, pointing to the parameter name containing a value which should be randomized before being sent:

```bash
sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5 | grep URI
```

# Calculated parameter bypass

Another similar mechanism is where a web application expects a proper parameter value to be calculated based on some other parameter value(s). Most often, one parameter value has to contain the message digest (e.g. h=MD5(id)) of another one. To bypass this, the option --eval should be used, where a valid Python code is being evaluated just before the request is being sent to the target:

```bash
sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 | grep URI
```

# IP address concealing

In case we want to conceal our IP address, or if a certain web application has a protection mechanism that blacklists our current IP address, we can try to use a proxy or the anonymity network Tor. A proxy can be set with the option **--proxy** (e.g. --proxy="socks4://177.39.187.70:33283"), where we should add a working proxy.

In addition to that, if we have a list of proxies, we can provide them to SQLMap with the option **--proxy-file**. This way, SQLMap will go sequentially through the list, and in case of any problems (e.g., blacklisting of IP address), it will just skip from current to the next from the list. 
The other option is Tor network use to provide an easy to use anonymization, where our IP can appear anywhere from a large list of Tor exit nodes. When properly installed on the local machine, there should be a SOCKS4 proxy service at the local port 9050 or 9150. By using switch **--tor**, SQLMap will automatically try to find the local port and use it appropriately.

# WAF bypass

Whenever we run SQLMap, As part of the initial tests, SQLMap sends a predefined malicious looking payload using a non-existent parameter name (e.g. ?pfov=...) to test for the existence of a WAF (Web Application Firewall). There will be a substantial change in the response compared to the original in case of any protection between the user and the target. For example, if one of the most popular WAF solutions (ModSecurity) is implemented, there should be a 406 - Not Acceptable response after such a request.

# User-agent blacklisting bypass

In case of immediate problems (e.g., HTTP error code 5XX from the start) while running SQLMap, one of the first things we should think of is the potential blacklisting of the default user-agent used by SQLMap (e.g. User-agent: sqlmap/1.4.9 (http://sqlmap.org)).

This is trivial to bypass with the switch **--random-agent**, which changes the default user-agent with a randomly chosen value from a large pool of values used by browsers.

# Tamper scripts

Finally, one of the most popular mechanisms implemented in SQLMap for bypassing WAF/IPS solutions is the so-called "tamper" scripts. Tamper scripts are a special kind of (Python) scripts written for modifying requests just before being sent to the target, in most cases to bypass some protection.

For example, one of the most popular tamper scripts between is replacing all occurrences of greater than operator (>) with NOT BETWEEN 0 AND #, and the equals operator (=) with BETWEEN # AND #. This way, many primitive protection mechanisms (focused mostly on preventing XSS attacks) are easily bypassed, at least for SQLi purposes.

Tamper scripts can be chained, one after another, within the **--tamper option** (e.g. --tamper=between,randomcase), where they are run based on their predefined priority. A priority is predefined to prevent any unwanted behavior, as some scripts modify payloads by modifying their SQL syntax (e.g. ifnull2ifisnull). In contrast, some tamper scripts do not care about the inner content (e.g. appendnullbyte).

To get a whole list of implemented tamper scripts, along with the description as above, switch **--list-tampers** can be used. We can also develop custom Tamper scripts for any custom type of attack, like a second-order SQLi.

# Miscellaneous bypass

Out of other protection bypass mechanisms, there are also two more that should be mentioned. The first one is the Chunked transfer encoding, turned on using the switch **--chunked**, which splits the POST request's body into so-called "chunks." Blacklisted SQL keywords are split between chunks in a way that the request containing them can pass unnoticed.

The other bypass mechanisms is the **HTTP parameter pollution (HPP)**, where payloads are split in a similar way as in case of --chunked between different same parameter named values (e.g. ?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users...), which are concatenated by the target platform if supporting it (e.g. ASP).