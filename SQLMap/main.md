SQLMap is a free and open-source penetration testing tool written in Python that automates the process of detecting and exploiting SQL injection (SQLi) flaws.

The technique characters BEUSTQ refers to the following:
- B: Boolean-based blind
- E: Error-based
- U: Union query-based
- S: Stacked queries
- T: Time-based blind
- Q: Inline queries

### Boolean-based blind SQL Injection

SQLMap exploits Boolean-based blind SQL Injection vulnerabilities through the differentiation of TRUE from FALSE query results, effectively retrieving 1 byte of information per request. The differentiation is based on comparing server responses to determine whether the SQL query returned TRUE or FALSE. This ranges from fuzzy comparisons of raw response content, HTTP codes, page titles, filtered text, and other factors.

- TRUE results are generally based on responses having none or marginal difference to the regular server response
- FALSE results are based on responses having substantial differences from the regular server response
- Boolean-based blind SQL Injection is considered as the most common SQLi type in web applications

### Error-based SQL injection

If the database management system (DBMS) errors are being returned as part of the server response for any database-related problems, then there is a probability that they can be used to carry the results for requested queries. In such cases, specialized payloads for the current DBMS are used, targeting the functions that cause known misbehaviors.

### UNION query-based

With the usage of UNION, it is generally possible to extend the original (vulnerable) query with the injected statements' results. This way, if the original query results are rendered as part of the response, the attacker can get additional results from the injected statements within the page response itself. This type of SQL injection is considered the fastest, as, in the ideal scenario, the attacker would be able to pull the content of the whole database table of interest with a single request.

### Stacked queries

Stacking SQL queries, also known as the "piggy-backing," is the form of injecting additional SQL statements after the vulnerable one. In case that there is a requirement for running non-query statements (e.g. INSERT, UPDATE or DELETE), stacking must be supported by the vulnerable platform (e.g., Microsoft SQL Server and PostgreSQL support it by default). SQLMap can use such vulnerabilities to run non-query statements executed in advanced features (e.g., execution of OS commands) and data retrieval similarly to time-based blind SQLi types.

### Time-based blind SQL injection

The principle of Time-based blind SQL Injection is similar to the Boolean-based blind SQL Injection, but here the response time is used as the source for the differentiation between TRUE or FALSE.

- TRUE response is generally characterized by the noticeable difference in the response time compared to the regular server response

- FALSE response should result in a response time indistinguishable from regular response times

Time-based blind SQL Injection is considerably slower than the boolean-based blind SQLi, since queries resulting in TRUE would delay the server response. This SQLi type is used in cases where Boolean-based blind SQL Injection is not applicable. For example, in case the vulnerable SQL statement is a non-query (e.g. INSERT, UPDATE or DELETE), executed as part of the auxiliary functionality without any effect to the page rendering process, time-based SQLi is used out of the necessity, as Boolean-based blind SQL Injection would not really work in this case.

### Inline queries

This type of injection embedded a query within the original query. Such SQL injection is uncommon, as it needs the vulnerable web app to be written in a certain way. Still, SQLMap supports this kind of SQLi as well.

### Out-of-band SQL injection

This is considered one of the most advanced types of SQLi, used in cases where all other types are either unsupported by the vulnerable web application or are too slow (e.g., time-based blind SQLi). SQLMap supports out-of-band SQLi through "DNS exfiltration," where requested queries are retrieved through DNS traffic.

By running the SQLMap on the DNS server for the domain under control (e.g. .attacker.com), SQLMap can perform the attack by forcing the server to request non-existent subdomains (e.g. foo.attacker.com), where foo would be the SQL response we want to receive. SQLMap can then collect these erroring DNS requests and collect the foo part, to form the entire SQL response.

# Basic scenario

There is a web app which accept the parameter ID in the URL. We want test if it is vulnerable to SQL injection.

Example of php vulnerable backend:
```php
$link = mysqli_connect($host, $username, $password, $database, 3306);
$sql = "SELECT * FROM users WHERE id = " . $_GET["id"] . " LIMIT 0, 1";
$result = mysqli_query($link, $sql);
if (!$result)
    die("<b>SQL error:</b> ". mysqli_error($link) . "<br>\n");
```

To run SQLMap against this example, located at the example URL http://www.example.com/vuln.php?id=1, would look like the following:

```bash
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch
```

# SQLMap output description

### URL content is stable

- Log message: **"target URL content is stable"**.

This means that there are no major changes between responses in case of continuous identical requests. This is important from the automation point of view since, in the event of stable responses, it is easier to spot differences caused by the potential SQLi attempts. While stability is important, SQLMap has advanced mechanisms to automatically remove the potential "noise" that could come from potentially unstable targets.

### Parameter appears to be dynamic

- Log message: **"GET parameter 'id' appears to be dynamic"**.

It is always desired for the tested parameter to be "dynamic," as it is a sign that any changes made to its value would result in a change in the response; hence the parameter may be linked to a database. In case the output is "static" and does not change, it could be an indicator that the value of the tested parameter is not processed by the target, at least in the current context.

### Parameter might be injectable

- Log message: **"heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')"**.

As discussed before, DBMS errors are a good indication of the potential SQLi. In this case, there was a MySQL error when SQLMap sends an intentionally invalid value was used (e.g. ```?id=1",)..).))'```), which indicates that the tested parameter could be SQLi injectable and that the target could be MySQL. It should be noted that this is not proof of SQLi, but just an indication that the detection mechanism has to be proven in the subsequent run.

### Parameter might be vulnerable to XSS attacks

- Log message: **"heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks"**.

While it is not its primary purpose, SQLMap also runs a quick heuristic test for the presence of an XSS vulnerability. In large-scale tests, where a lot of parameters are being tested with SQLMap, it is nice to have these kinds of fast heuristic checks, especially if there are no SQLi vulnerabilities found.

### Back-end DBMS is '...'

- Log message: **"it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n]"**.

In a normal run, SQLMap tests for all supported DBMSes. In case that there is a clear indication that the target is using the specific DBMS, we can narrow down the payloads to just that specific DBMS.

### Level/risk values
- Log message: **"for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n]"**.

If there is a clear indication that the target uses the specific DBMS, it is also possible to extend the tests for that same specific DBMS beyond the regular tests.
This basically means running all SQL injection payloads for that specific DBMS, while if no DBMS were detected, only top payloads would be tested.

### Reflective values found
- Log message: **"reflective value(s) found and filtering out"**.

Just a warning that parts of the used payloads are found in the response. This behavior could cause problems to automation tools, as it represents the junk. However, SQLMap has filtering mechanisms to remove such junk before comparing the original page content.

### Parameter appears to be injectable

- Log message: **"GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="luther")"**.

This message indicates that the parameter appears to be injectable, though there is still a chance for it to be a false-positive finding. In the case of boolean-based blind and similar SQLi types (e.g., time-based blind), where there is a high chance of false-positives, at the end of the run, SQLMap performs extensive testing consisting of simple logic checks for removal of false-positive findings.

### Time-based comparison statistical model
- Log message: **"time-based comparison requires a larger statistical model, please wait........... (done)"**.


SQLMap uses a statistical model for the recognition of regular and (deliberately) delayed target responses. For this model to work, there is a requirement to collect a sufficient number of regular response times. This way, SQLMap can statistically distinguish between the deliberate delay even in the high-latency network environments.

### Extending UNION query injection technique tests

- Log message: **"automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found"**.

UNION-query SQLi checks require considerably more requests for successful recognition of usable payload than other SQLi types. To lower the testing time per parameter, especially if the target does not appear to be injectable, the number of requests is capped to a constant value (i.e., 10) for this type of check. However, if there is a good chance that the target is vulnerable, especially as one other (potential) SQLi technique is found, SQLMap extends the default number of requests for UNION query SQLi, because of a higher expectancy of success.

### Technique appears to be usable

- Log message: **"ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test"**.

### Parameter is vulnerable
- Log message: **"GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]"**.

This is one of the most important messages of SQLMap, as it means that the parameter was found to be vulnerable to SQL injections. In the regular cases, the user may only want to find at least one injection point (i.e., parameter) usable against the target. However, if we were running an extensive test on the web application and want to report all potential vulnerabilities, we can continue searching for all vulnerable parameters.

### Sqlmap identified injection points
- Log message: **"sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:"**.

Following after is a listing of all injection points with type, title, and payloads, which represents the final proof of successful detection and exploitation of found SQLi vulnerabilities. It should be noted that SQLMap lists only those findings which are provably exploitable (i.e., usable).

### Data logged to text files

- Log message: **"fetched data logged to text files under '/home/user/.sqlmap/output/www.example.com'"**.

This indicates the local file system location used for storing all logs, sessions, and output data for a specific target - in this case, www.example.com. After such an initial run, where the injection point is successfully detected, all details for future runs are stored inside the same directory's session files. This means that SQLMap tries to reduce the required target requests as much as possible, depending on the session files' data.