# SQLMap data exfiltration

For such purpose, SQLMap has a predefined set of queries for all supported DBMSes, where each entry represents the SQL that must be run at the target to retrieve the desired content. For example, if a user wants to retrieve the "banner" (switch **--banner**) for the target based on MySQL DBMS, the VERSION() query will be used for such purpose.
In case of retrieval of the current user name (switch **--current-user**), the CURRENT_USER() query will be used.

# Basic DB data enumeration

Usually, after a successful detection of an SQLi vulnerability, we can begin the enumeration of basic details from the database, such as the hostname of the vulnerable target (**--hostname**), current user's name (**--current-user**), current database name (**--current-db**), or password hashes (**--passwords**). SQLMap will skip SQLi detection if it has been identified earlier and directly start the DBMS enumeration process.

Enumeration usually starts with the retrieval of the basic information:

- Database version banner (switch **--banner**)
- Current user name (switch **--current-user**)
- Current database name (switch **--current-db**)
- Checking if the current user has DBA (administrator) rights.

The following SQLMap command does all of the above:

```bash
sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba
```

# Table enumeration
In most common scenarios, after finding the current database name (i.e. testdb), the retrieval of table names would be by using the --tables option and specifying the DB name with -D testdb, is as follows:

```bash
sqlmap -u "http://www.example.com/?id=1" --tables -D testdb
```

After spotting the table name of interest, retrieval of its content can be done by using the --dump option and specifying the table name with -T users, as follows:

```bash
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb
```

# Table/row enumeration
When dealing with large tables with many columns and/or rows, we can specify the columns (e.g., only name and surname columns) with the -C option, as follows:

```bash
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname
```
To narrow down the rows based on their ordinal number(s) inside the table, we can specify the rows with the --start and --stop options (e.g., start from 2nd up to 3rd entry), as follows:

```bash
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --start=2 --stop=3
```

# Conditional enumeration
If there is a requirement to retrieve certain rows based on a known WHERE condition (e.g. name LIKE 'f%'), we can use the option --where, as follows:
```bash
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"
```

# Full DB enumeration

Instead of retrieving content per single-table basis, we can retrieve all tables inside the database of interest by skipping the usage of option -T altogether (e.g. --dump -D testdb). **By simply using the switch --dump without specifying a table with -T, all of the current database content will be retrieved**. As for the **--dump-all switch, all the content from all the databases will be retrieved**.

In such cases, a user is also advised to include the switch **--exclude-sysdbs** (e.g. --dump-all --exclude-sysdbs), which will instruct SQLMap to skip the retrieval of content from system databases, as it is usually of little interest for pentesters.

# DB schema enumeration
If we wanted to retrieve the structure of all of the tables so that we can have a complete overview of the database architecture, we could use the switch --schema:

```bash
sqlmap -u "http://www.example.com/?id=1" --schema
```

# Searching for specific data

When dealing with complex database structures with numerous tables and columns, we can search for databases, tables, and columns of interest, by using the --search option. This option enables us to search for identifier names by using the LIKE operator. For example, if we are looking for all of the table names containing the keyword user, we can run SQLMap as follows:

```bash
 sqlmap -u "http://www.example.com/?id=1" --search -T user
```

With the folloqing we search for everything that contains the string "pass":

```bash
sqlmap -u "http://www.example.com/?id=1" --search -C pass
```

# Password enumeration and cracking

Once we identify a table containing passwords (e.g. master.users), we can retrieve that table with the -T option, as previously shown:

```bash
sqlmap -u "http://www.example.com/?id=1" --dump -D master -T users
```

SQLMap has automatic password hashes cracking capabilities. Upon retrieving any value that resembles a known hash format, SQLMap prompts us to perform a dictionary-based attack on the found hashes.

Hash cracking attacks are performed in a multi-processing manner, based on the number of cores available on the user's computer. Currently, there is an implemented support for cracking 31 different types of hash algorithms, with an included dictionary containing 1.4 million entries (compiled over the years with most common entries appearing in publicly available password leaks). Thus, if a password hash is not randomly chosen, there is a good probability that SQLMap will automatically crack it.

# DB Users Password Enumeration and Cracking

Apart from user credentials found in DB tables, we can also attempt to dump the content of system tables containing database-specific credentials (e.g., connection credentials). To ease the whole process, SQLMap has a special switch --passwords designed especially for such a task:

```bash
sqlmap -u "http://www.example.com/?id=1" --passwords --batch
```

