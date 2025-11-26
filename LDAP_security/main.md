**LDAP (Lightweight Directory Access Protocol)** is a protocol used to access and manage directory information. A directory is a hierarchical data store that contains information about network resources such as users, groups, computers, printers, and other devices. LDAP provides some excellent functionality:

| Functionality | Description |
| :--- | :--- |
| **Efficient** | Efficient and fast queries and connections to directory services, thanks to its lean query language and non-normalised data storage. |
| **Global naming model** | Supports multiple independent directories with a global naming model that ensures unique entries. |
| **Extensible and flexible** | This helps to meet future and local requirements by allowing custom attributes and schemas. |
| **Compatibility** | It is compatible with many software products and platforms as it runs over TCP/IP and SSL directly, and it is **platform-independent**, suitable for use in heterogeneous environments with various operating systems. |
| **Authentication** | It provides **authentication** mechanisms that enable users to **sign on once** and access multiple resources on the server securely.

However, it also suffers some significant issues:

| Functionality | Description |
| :--- | :--- |
| **Compliance** | Directory servers **must be LDAP compliant** for service to be deployed, which may **limit the choice** of vendors and products. |
| **Complexity** | **Difficult to use and understand** for many developers and administrators, who may not know how to configure LDAP clients correctly or use it securely. |
| **Encryption** | LDAP **does not encrypt its traffic by default**, which exposes sensitive data to potential eavesdropping and tampering. LDAPS (LDAP over SSL) or StartTLS must be used to enable encryption. |
| **Injection** | **Vulnerable to LDAP injection attacks**, where malicious users can manipulate LDAP queries and **gain unauthorised access** to data or resources. To prevent such attacks, input validation and output encoding must be implemented. |

LDAP is commonly used for providing a central location for accessing and managing directory services. Directory services are collections of information about the organisation, its users, and assets–like usernames and passwords. LDAP enables organisations to store, manage, and secure this information in a standardised way.


There are two popular implementations of LDAP: OpenLDAP, an open-source software widely used and supported, and Microsoft Active Directory, a Windows-based implementation that seamlessly integrates with other Microsoft products and services.

*Although LDAP and AD are related, they serve different purposes. LDAP is a protocol that specifies the method of accessing and modifying directory services, whereas AD is a directory service that stores and manages user and computer data. While LDAP can communicate with AD and other directory services, it is not a directory service itself. AD offers extra functionalities such as policy administration, single sign-on, and integration with various Microsoft products*.


LDAP works by using a client-server architecture. A client sends an LDAP request to a server, which searches the directory service and returns a response to the client. LDAP is a protocol that is simpler and more efficient than X.500, on which it is based. It uses a client-server model, where clients send requests to servers using LDAP messages encoded in ASN.1 (Abstract Syntax Notation One) and transmitted over TCP/IP (Transmission Control Protocol/Internet Protocol). The servers process the requests and send back responses using the same format. LDAP supports various requests, such as bind, unbind, search, compare, add, delete, modify, etc.

# LDAP injections

LDAP injection is an attack that exploits web applications that use LDAP (Lightweight Directory Access Protocol) for authentication or storing user information. The attacker can inject malicious code or characters into LDAP queries to alter the application's behaviour, bypass security measures, and access sensitive data stored in the LDAP directory.

To test for LDAP injection, you can use input values that contain special characters or operators that can change the query's meaning:

| Input | Description |
| :--- | :--- |
| **\*** | An asterisk `*` can **match any number of characters**. |
| **( )** | Parentheses `( )` can **group expressions**. |
| **\|** | A vertical bar `\|` can perform **logical OR**. |
| **&** | An ampersand `&` can perform **logical AND**. |
| **(cn=*)** | Input values that try to bypass authentication or authorisation checks by injecting conditions that **always evaluate to true** can be used. For example, `(cn=*)` or `(objectClass=*)` can be used as input values for a username or password fields. |



LDAP injection attacks are similar to SQL injection attacks but target the LDAP directory service instead of a database.

For example, suppose an application uses the following LDAP query to authenticate users: `(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))´

In this query, $username and $password contain the user's login credentials. An attacker could inject the * character into the $username or $password field to modify the LDAP query and bypass authentication.

If an attacker injects the * character into the $username field, the LDAP query will match any user account with any password. This would allow the attacker to gain access to the application with any password.

Typically ldap server **runs on port 389**.
