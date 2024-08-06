Most modern web applications utilize a database structure on the back-end. Such databases are used to store and retrieve data related to the web application, from actual web content to user information and content, and so on. To make the web applications dynamic, the web application has to interact with the database in real-time. As HTTP(S) requests arrive from the user, the web application's back-end will issue queries to the database to build the response. These queries can include information from the HTTP(S) request or other relevant information.

Many types of injection vulnerabilities are possible within web applications, such as HTTP injection, code injection, and command injection. The most common example, however, is SQL injection. A SQL injection occurs when a malicious user attempts to pass input that changes the final SQL query sent by the web application to the database, enabling the user to perform other unintended SQL queries directly against the database.

There are many ways to accomplish this. To get a SQL injection to work, the attacker must first inject SQL code and then subvert the web application logic by changing the original query or executing a completely new one. First, the attacker has to inject code outside the expected user input limits, so it does not get executed as simple user input.

# SQL syntax

SQL syntax can differ from one RDBMS to another. However, they are all required to follow the ISO standard for Structured Query Language. We will be following the MySQL/MariaDB syntax for the examples shown. SQL can be used to perform the following actions:

- Retrieve data
- Update data
- Delete data
- Create new tables and databases
- Add / remove users
- Assign permissions to these users

# MySQL CLI utility

The mysql utility is used to authenticate to and interact with a MySQL/MariaDB database. The -u flag is used to supply the username and the -p flag for the password. The -p flag should be passed empty, so we are prompted to enter the password and do not pass it directly on the command line since it could be stored in cleartext in the bash_history file.
Again, it is also possible to use the password directly in the command, though this should be avoided, as it could lead to the password being kept in logs and terminal history (Tip: There shouldn't be any spaces between '-p' and the password).


# Example of PHP vulnerable code to connect to DB

```php
$conn = new mysqli("localhost", "root", "password", "users");
$query = "select * from logins";
$result = $conn->query($query);
```

Then, the query's output will be stored in $result, and we can print it to the page or use it in any other way. The below PHP code will print all returned results of the SQL query in new lines:

```php
while($row = $result->fetch_assoc() ){
	echo $row["name"]."<br>";
}
```


Web applications also usually use user-input when retrieving data. For example, when a user uses the search function to search for other users, their search input is passed to the web application, which uses the input to search within the databases:

```php
$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```
**If we use user-input within an SQL query, and if not securely coded, it may cause a variety of issues, like SQL Injection vulnerabilities**.

In the above example, we accept user input and pass it directly to the SQL query without sanitization. Sanitization refers to the removal of any special characters in user-input, in order to break any injection attempts.

Example:

```sql
select * from logins where username like '%$searchInput'
```

Injection code: ```'%1'; DROP TABLE users;'```

The resulting sql is:

```sql
select * from logins where username like '%1'; DROP TABLE users;'
```

The previous example of SQL injection would return an error (Error: near line 1: near "'": syntax error). This is because of the last trailing character, where we have a single extra quote (') that is not closed, which causes a SQL syntax error when executed.
To have a successful injection, we must ensure that the newly modified SQL query is still valid and does not have any syntax errors after our injection. In most cases, we would not have access to the source code to find the original SQL query and develop a proper SQL injection to make a valid SQL query. So, how would we be able to inject into the SQL query then successfully?

One answer is by using comments, and we will discuss this in a later section. Another is to make the query syntax work by passing in multiple single quotes, as we will discuss next (').

# Types of SQL injections

In simple cases, the output of both the intended and the new query may be printed directly on the front end, and we can directly read it. This is known as **In-band SQL injection**, and it has two types: **Union Based** and **Error Based**.

With **Union Based SQL injection**, we may have to specify the exact location, 'i.e., column', which we can read, so the query will direct the output to be printed there. As for **Error Based SQL injection**, it is used when we can get the PHP or SQL errors in the front-end, and so we may intentionally cause an SQL error that returns the output of our query.


In more complicated cases, we may not get the output printed, so we may utilize SQL logic to retrieve the output character by character. This is known as **Blind SQL injection**, and it also has two types: **Boolean Based** and **Time Based**.

With **Boolean Based SQL injection**, we can use SQL conditional statements to control whether the page returns any output at all, 'i.e., original query response,' if our conditional statement returns true. As for **Time Based SQL injections**, we use SQL conditional statements that delay the page response if the conditional statement returns true using the Sleep() function.


Finally, in some cases, we may not have direct access to the output whatsoever, so we may have to direct the output to a remote location, 'i.e., DNS record,' and then attempt to retrieve it from there. This is known as **Out-of-band** SQL injection.


# Example of an injection in a simple login page

The backend executed query is:

```sql
SELECT * FROM logins WHERE username='admin' AND password = 'p@ssw0rd';
```
The page takes in the credentials, then uses the AND operator to select records matching the given username and password. If the MySQL database returns matched records, the credentials are valid, so the PHP code would evaluate the login attempt condition as true. If the condition evaluates to true, the admin record is returned, and our login is validated.

Before we start subverting the web application's logic and attempting to bypass the authentication, we first have to test whether the login form is vulnerable to SQL injection. To do that, we will try to add one of the below payloads after our username and see if it causes any errors or changes how the page behaves:

- Symbol: ```', URL encoded: %27```;
- Symbol: ```", URL encoded: %22```;
- Symbol: ```#, URL encoded: %23```;
- Symbol: ```;, URL encoded: %3B```;
- Symbol: ```), URL encoded: %29```;

### OR injection
We would need the query always to return true, regardless of the username and password entered, to bypass the authentication. To do this, we can abuse the OR operator in our SQL injection.

**The MySQL documentation for operation precedence states that the AND operator would be evaluated before the OR operator**. This means that if there is at least one TRUE condition in the entire query along with an OR operator, the entire query will evaluate to TRUE since the OR operator returns TRUE if one of its operands is TRUE.

Injection payload: ```admin' or '1'='1```

Resulting SQL:

```sql
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';
```

**The AND operator will be evaluated first, and it will return false. Then, the OR operator would be evalutated, and if either of the statements is true, it would return true. Since 1=1 always returns true, this query will return true, and it will grant us access**.

