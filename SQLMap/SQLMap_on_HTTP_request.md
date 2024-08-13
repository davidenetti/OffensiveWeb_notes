# Set up SQLMap request against a specific target using cURL

We can use the feature **copy as cURL** within the "network" panel inside Chrome or Firefox of all modern browsers.
Then, we paste this into the command line, and change the original command from curl to sqlmap.


# GET/POST requests

In the most common scenario, GET parameters are provided with the usage of option -u/--url, as in the previous example. As for testing POST data, the --data flag can be used, as follows:

```bash
sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
```

In such cases, POST parameters uid and name will be tested for SQLi vulnerability. For example, if we have a clear indication that the parameter uid is prone to an SQLi vulnerability, we could narrow down the tests to only this parameter using -p uid. Otherwise, we could mark it inside the provided data with the usage of special marker * as follows:

```bash
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
```

# Full HTTP request

If we need to specify a complex HTTP request with lots of different header values and an elongated POST body, we can use the -r flag. With this option, SQLMap is provided with the "request file," containing the whole HTTP request inside a single textual file. In a common scenario, such HTTP request can be captured from within a specialized proxy application (e.g. Burp) and written into the request file.

To run SQLMap with an HTTP request file, we use the -r flag, as follows:

```bash
sqlmap -r req.txt
```

# Custom SQLMap requests

If we wanted to craft complicated requests manually, there are numerous switches and options to fine-tune SQLMap.

For example, if there is a requirement to **specify the (session) cookie value** to PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c option --cookie would be used as follows:

```bash
sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
```

The same effect can be done with the usage of option -H/--header:

```bash
sqlmap ... -H='Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
```

We can apply the same to options like **--host, --referer, and -A/--user-agent**, which are used to specify the same HTTP headers' values.

Furthermore, there is a switch **--random-agent** designed to randomly select a User-agent header value from the included database of regular browser values. This is an important switch to remember, as more and more protection solutions automatically drop all HTTP traffic containing the recognizable default SQLMap's User-agent value (e.g. User-agent: sqlmap/1.4.9.12#dev (http://sqlmap.org)). Alternatively, the **--mobile** switch can be used to imitate the smartphone by using that same header value.

Also, if we wanted to specify an alternative HTTP method, other than GET and POST (e.g., PUT), we can utilize the option --method, as follows:

```bash
sqlmap -u www.target.com --data='id=1' --method PUT
```


# Custom HTTP requests

Apart from the most common form-data POST body style (e.g. id=1), SQLMap also supports JSON formatted (e.g. {"id":1}) and XML formatted (e.g. <element><id>1</id></element>) HTTP requests.

We need to use the **--data** switch.

# Store the traffic

The -t option stores the whole traffic content to an output file:

```bash
 sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt
```

# Verbose output

Another useful flag is the -v option, which raises the verbosity level of the console output:

```bash
sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch
```

As we can see, the -v 6 option will directly print all errors and full HTTP request to the terminal so that we can follow along with everything SQLMap is doing in real-time.

# Using proxy

Finally, we can utilize the **--proxy** option to redirect the whole traffic through a (MiTM) proxy (e.g., Burp). This will route all SQLMap traffic through Burp, so that we can later manually investigate all requests, repeat them, and utilize all features of Burp with these requests.


# Attack tuning

### Prefix/Suffix

There is a requirement for special prefix and suffix values in rare cases, not covered by the regular SQLMap run.
For such runs, options --prefix and --suffix can be used as follows:

```bash
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
```

This will result in an enclosure of all vector values between the static prefix %')) and the suffix -- -.
For example, if the vulnerable code at the target is:

```php
$query = "SELECT id,name,surname FROM users WHERE id LIKE (('" . $_GET["q"] . "')) LIMIT 0,1";
$result = mysqli_query($link, $query);
```

The vector UNION ALL SELECT 1,2,VERSION(), bounded with the prefix %')) and the suffix -- -, will result in the following (valid) SQL statement at the target:

```sql
SELECT id,name,surname FROM users WHERE id LIKE (('test%')) UNION ALL SELECT 1,2,VERSION()-- -')) LIMIT 0,1
```

### Level/risk

By default, SQLMap combines a predefined set of most common boundaries (i.e., prefix/suffix pairs), along with the vectors having a high chance of success in case of a vulnerable target. Nevertheless, there is a possibility for users to use bigger sets of boundaries and vectors, already incorporated into the SQLMap.

For such demands, the options --level and --risk should be used:
- The option --level (1-5, default 1) extends both vectors and boundaries being used, based on their expectancy of success (i.e., the lower the expectancy, the higher the level);
- The option --risk (1-3, default 1) extends the used vector set based on their risk of causing problems at the target side (i.e., risk of database entry loss or denial-of-service).

### Advanced tuning

- **--code**: this option to filter out unwanted responses. Example --code=200 will keep only responses with status code 200;
- **--string**: this option could be used to filter out responses which not contains a specific string. Example: --string==success will keep only responses which contains the string "success";
- **--text-only**: when dealing with a lot of hidden content, such as certain HTML page behaviors tags (e.g. ```<script>, <style>, <meta>```, etc.), we can use this switch, which removes all the HTML tags, and bases the comparison only on the textual (i.e., visible) content.
- **--Thechnique**: in some special cases, we have to narrow down the used payloads only to a certain type. For example, if the time-based blind payloads are causing trouble in the form of response timeouts, or if we want to force the usage of a specific SQLi payload type, the option --technique can specify the SQLi technique to be used. For example, if we want to skip the time-based blind and stacking SQLi payloads and only test for the boolean-based blind, error-based, and UNION-query payloads, we can specify these techniques with --technique=BEU.
- **--union-cols**: in some cases, UNION SQLi payloads require extra user-provided information to work. If we can manually find the exact number of columns of the vulnerable SQL query, we can provide this number to SQLMap with the option --union-cols (e.g. --union-cols=17). In case that the default "dummy" filling values used by SQLMap -NULL and random integer are not compatible with values from results of the vulnerable SQL query, we can specify an alternative value instead (e.g. --union-char='a'). Furthermore, in case there is a requirement to use an appendix at the end of a UNION query in the form of the FROM ```<table>``` (e.g., in case of Oracle), we can set it with the option --union-from (e.g. --union-from=users). Failing to use the proper FROM appendix automatically could be due to the inability to detect the DBMS name before its usage.

