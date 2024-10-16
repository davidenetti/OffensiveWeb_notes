**Insecure Direct Object References (IDOR)** vulnerabilities are among the most common web vulnerabilities and can significantly impact the vulnerable web application. IDOR vulnerabilities occur when a web application exposes a direct reference to an object, like a file or a database resource, which the end-user can directly control to obtain access to other similar objects. If any user can access any resource due to the lack of a solid access control system, the system is considered to be vulnerable.

For example, if users request access to a file they recently uploaded, they may get a link to it such as (download.php?file_id=123). So, as the link directly references the file with (file_id=123), what would happen if we tried to access another file (which may not belong to us) with (download.php?file_id=124)? If the web application does not have a proper access control system on the back-end, we may be able to access any file by sending a request with its file_id. In many cases, we may find that the id is easily guessable, making it possible to retrieve many files or resources that we should not have access to based on our permissions.

As mentioned earlier, IDOR vulnerabilities can have a significant impact on web applications. The most basic example of an IDOR vulnerability is accessing private files and resources of other users that should not be accessible to us, like personal files or credit card data, which is known as **IDOR Information Disclosure Vulnerabilities**. Depending on the nature of the exposed direct reference, the vulnerability may even allow the modification or deletion of other users' data, which may lead to a complete account takeover.

IDOR vulnerabilities may also lead to the elevation of user privileges from a standard user to an administrator user, with **IDOR Insecure Function Calls**. For example, many web applications expose URL parameters or APIs for admin-only functions in the front-end code of the web application and disable these functions for non-admin users. However, if we had access to such parameters or APIs, we may call them with our standard user privileges. Suppose the back-end did not explicitly deny non-admin users from calling these functions. In that case, we may be able to perform unauthorized administrative operations, like changing users' passwords or granting users certain roles, which may eventually lead to a total takeover of the entire web application.

# Identifying IDORs

The very first step of exploiting IDOR vulnerabilities is identifying Direct Object References. Whenever we receive a specific file or resource, we should study the HTTP requests to look for URL parameters or APIs with an object reference (e.g. ?uid=1 or ?filename=file_1.pdf). These are mostly found in URL parameters or APIs but may also be found in other HTTP headers, like cookies.

### AJAX (JavaScript)

We may also be able to identify unused parameters or APIs in the front-end code in the form of JavaScript AJAX calls. Some web applications developed in JavaScript frameworks may insecurely place all function calls on the front-end and use the appropriate ones based on the user role.

For example, if we did not have an admin account, only the user-level functions would be used, while the admin functions would be disabled. However, we may still be able to find the admin functions if we look into the front-end JavaScript code and may be able to identify AJAX calls to specific end-points or APIs that contain direct object references. If we identify direct object references in the JavaScript code, we can test them for IDOR vulnerabilities.

```javascript
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}
```

The above function may never be called when we use the web application as a non-admin user. However, if we locate it in the front-end code, we may test it in different ways to see whether we can call it to perform changes, which would indicate that it is vulnerable to IDOR. We can do the same with back-end code if we have access to it (e.g., open-source web applications).

### Hashing/encoding

Some web applications may not use simple sequential numbers as object references but may encode the reference or hash it instead. If we find such parameters using encoded or hashed values, we may still be able to exploit them if there is no access control system on the back-end.

Suppose the reference was encoded with a common encoder (e.g. base64). In that case, we could decode it and view the plaintext of the object reference, change its value, and then encode it again to access other data. For example, if we see a reference like (?filename=ZmlsZV8xMjMucGRm), we can immediately guess that the file name is base64 encoded (from its character set), which we can decode to get the original object reference of (file_123.pdf). Then, we can try encoding a different object reference (e.g. file_124.pdf) and try accessing it with the encoded object reference (?filename=ZmlsZV8xMjQucGRm), which may reveal an IDOR vulnerability if we were able to retrieve any data.

On the other hand, **the object reference may be hashed**, like (download.php?filename=c81e728d9d4c2f636f067f89cc14862c). At a first glance, we may think that this is a secure object reference, as it is not using any clear text or easy encoding. However, if we look at the source code, we may see what is being hashed before the API call is made:

```javascript
$.ajax({
    url:"download.php",
    type: "post",
    dataType: "json",
    data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
    success:function(result){
        //
    }
});
```
In this case, we can see that code uses the filename and hashing it with CryptoJS.MD5, making it easy for us to calculate the filename for other potential files. Otherwise, we may manually try to identify the hashing algorithm being used (e.g., with hash identifier tools) and then hash the filename to see if it matches the used hash. Once we can calculate hashes for other files, we may try downloading them, which may reveal an IDOR vulnerability if we can download any files that do not belong to us.

### Compare user roles

If we want to perform more advanced IDOR attacks, we may need to register multiple users and compare their HTTP requests and object references. This may allow us to understand how the URL parameters and unique identifiers are being calculated and then calculate them for other users to gather their data.

For example, if we had access to two different users, one of which can view their salary after making the following API call:

```json
{
  "attributes" : 
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"

}
```

The second user may not have all of these API parameters to replicate the call and should not be able to make the same call as User1. However, with these details at hand, we can try repeating the same API call while logged in as User2 to see if the web application returns anything. Such cases may work if the web application only requires a valid logged-in session to make the API call but has no access control on the back-end to compare the caller's session with the data being called.

If this is the case, and we can calculate the API parameters for other users, this would be an IDOR vulnerability. Even if we could not calculate the API parameters for other users, we would still have identified a vulnerability in the back-end access control system and may start looking for other object references to exploit.

# IDOR Enumeration


### Scenario

Our web application assumes that we are logged in as an employee with user id uid=1 to simplify things. This would require us to log in with credentials in a real web application, but the rest of the attack would be the same. Once we click on Documents, we are redirected to /documents.php.

When we get to the Documents page, we see several documents that belong to our user. These can be files uploaded by our user or files set for us by another department (e.g., HR Department). Checking the file links, we see that they have individual names:
- /documents/Invoice_1_09_2021.pdf
- /documents/Report_1_10_2021.pdf

We see that the files have a predictable naming pattern, as the file names appear to be using the user uid and the month/year as part of the file name, which may allow us to fuzz files for other users. This is the most basic type of IDOR vulnerability and is called **static file IDOR**.

We see that the page is setting our uid with a GET parameter in the URL as (documents.php?uid=1). If the web application uses this uid GET parameter as a direct reference to the employee records it should show, we may be able to view other employees' documents by simply changing this value. If the back-end end of the web application does have a proper access control system, we will get some form of Access Denied. However, given that the web application passes as our uid in clear text as a direct reference, this may indicate poor web application design, leading to arbitrary access to employee records.

When we try changing the uid to ?uid=2, we don't notice any difference in the page output, as we are still getting the same list of documents, and may assume that it still returns our own documents.
However, we must be attentive to the page details during any web pentest and always keep an eye on the source code and page size. If we look at the linked files, or if we click on them to view them, we will notice that these are indeed different files, which appear to be the documents belonging to the employee with uid=2:

- /documents/Invoice_2_08_2020.pdf
- /documents/Report_2_12_2020.pdf

### Mass enumeration

We can either use a tool like Burp Intruder or ZAP Fuzzer to retrieve all files or write a small bash script to download all files, which is what we will do.

```bash
#!/bin/bash
url="http://SERVER_IP:PORT"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done
```

When we run the script, it will download all documents from all employees with uids between 1-10, thus successfully exploiting the IDOR vulnerability to mass enumerate the documents of all employees.


# Bypass encoded references

### Scenario

A POST request to download.php intercepted with Burp shown the following:

```
contract=cdd96d3cc73d1dbdaffa03cc6cd7339b
```

Using a download.php script to download files is a common practice to avoid directly linking to files, as that may be exploitable with multiple web attacks. In this case, the web application is not sending the direct reference in cleartext but appears to be hashing it in an md5 format. Hashes are one-way functions, so we cannot decode them to see their original values.

We can attempt to hash various values, like uid, username, filename, and many others, and see if any of their md5 hashes match the above value. If we find a match, then we can replicate it for other users and collect their files. For example, let's try to compare the md5 hash of our uid, and see if it matches the above hash:

```bash
echo -n 1 | md5sum

c4ca4238a0b923820dcc509a6f75849b 
```

Unfortunately, the hashes do not match. We can attempt this with various other fields, but none of them matches our hash. In advanced cases, we may also utilize Burp Comparer and fuzz various values and then compare each to our hash to see if we find any matches. In this case, the md5 hash could be for a unique value or a combination of values, which would be very difficult to predict, making this direct reference a **Secure Direct Object Reference**. However, there's one fatal flaw in this web application.

# Function disclosure

As most modern web applications are developed using JavaScript frameworks, like Angular, React, or Vue.js, many web developers may make the mistake of performing sensitive functions on the front-end, which would expose them to attackers. For example, if the above hash was being calculated on the front-end, we can study the function and then replicate what it's doing to calculate the same hash. Luckily for us, this is precisely the case in this web application.

If we take a look at the link in the source code, we see that it is calling a JavaScript function with javascript:downloadContract('1'). Looking at the downloadContract() function in the source code, we see the following:

```javascript
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```

This function appears to be sending a POST request with the contract parameter, which is what we saw above. The value it is sending is an md5 hash using the CryptoJS library, which also matches the request we saw earlier. So, the only thing left to see is what value is being hashed.

In this case, the value being hashed is btoa(uid), which is the base64 encoded string of the uid variable, which is an input argument for the function. Going back to the earlier link where the function was called, we see it calling downloadContract('1'). **So, the final value being used in the POST request is the base64 encoded string of 1, which was then md5 hashed**.

\
\
Once again, let us write a simple bash script to retrieve all employee contracts. More often than not, this is the easiest and most efficient method of enumerating data and files through IDOR vulnerabilities.

We can start by calculating the hash for each of the first ten employees using the same previous command while using **tr -d** to remove the **trailing - characters**, as follows:

```bash
for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done

cdd96d3cc73d1dbdaffa03cc6cd7339b
0b7e7dee87b1c3b98e72131173dfbbbf
0b24df25fe628797b3a50ae0724d2730
f7947d50da7a043693a592b4db43b0a1
8b9af1f7f76daf0f02bd9c48c4a2e3d0
006d1236aee3f92b8322299796ba1989
b523ff8d1ced96cef9c86492e790c2fb
d477819d240e7d3dd9499ed8d23e7158
3e57e65a34ffcb2e93cb545d024f5bde
5d4aace023dc088767b4e08c79415dcd
```

Next, we can make a POST request on download.php with each of the above hashes as the contract value, which should give us our final script:

```bash
#!/bin/bash

for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
    done
done
```


Another script example encoding in URL-encode the query parameter:
```bash
#!/bin/bash
url="http://IP:PORT/download.php"

for i in {1..20}; do
        for hash in $(echo -n $i | base64 -w 0);do
		echo $hash
                curl -sOJ -G $url --data-urlencode "contract=$hash"
        done
done

```


# IDOR in insecure APIs

IDOR vulnerabilities may also exist in function calls and APIs, and exploiting them would allow us to perform various actions as other users.

While **IDOR Information Disclosure Vulnerabilities** allow us to read various types of resources, **IDOR Insecure Function Calls** enable us to call APIs or execute functions as another user. Such functions and APIs can be used to change another user's private information, reset another user's password, or even buy items using another user's payment information.

### Identifying insecure APIs

We can intecercept with Burp a call to something that looks like an API. For example a form that allow an user to change his/her informations. For example:
- Using Burp we intercerpt a request which sends a **PUT** to the "/profile/api.php/profile/1" endpoint;
- Tipically a PUT is an API that makes an update.

This is an example of body about the PUT request we are talking about:
```json
{
    "uid": 1,
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "employee",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
    "about": "A Release is like a boat. 80% of the holes plugged is not good enough."
}
```
We see that the PUT request includes a few hidden parameters, like uid, uuid, and most interestingly role, which is set to employee. The web application also appears to be setting the user access privileges (e.g. role) on the client-side, in the form of our Cookie: role=employee cookie, which appears to reflect the role specified for our user.

This is a **common security issue**. The access control privileges are sent as part of the client's HTTP request, either as a cookie or as part of the JSON request, leaving it under the client's control, which could be manipulated to gain more privileges.

### Exploiting insecure APIs

We know that we can change the full_name, email, and about parameters, as these are the ones under our control in the HTML form in the /profile web page. So, let's try to manipulate the other parameters.

There are a few things we could try in this case:
1. Change our uid to another user's uid, such that we can take over their accounts;
2. Change another user's details, which may allow us to perform several web attacks;
3. Create new users with arbitrary details, or delete existing users;
4. Change our role to a more privileged role (e.g. admin) to be able to perform more actions.


**Let's start by changing our uid to another user's uid (e.g. "uid": 2). However, any number we set other than our own uid gets us a response of uid mismatch**:

The web application appears to be comparing the request's uid to the API endpoint (/1). This means that a form of access control on the back-end prevents us from arbitrarily changing some JSON parameters, which might be necessary to prevent the web application from crashing or returning errors.

**Perhaps we can try changing another user's details. We'll change the API endpoint to /profile/api.php/profile/2, and change "uid": 2 to avoid the previous uid mismatch**:

As we can see, this time, we get an error message saying uuid mismatch. The web application appears to be checking if the uuid value we are sending matches the user's uuid. Since we are sending our own uuid, our request is failing. This appears to be another form of access control to prevent users from changing another user's details.

**Next, let's see if we can create a new user with a POST request to the API endpoint. We can change the request method to POST, change the uid to a new uid, and send the request to the API endpoint of the new uid**:

We get an error message saying Creating new employees is for admins only. The same thing happens when we send a Delete request, as we get Deleting employees is for admins only. The web application might be checking our authorization through the role=employee cookie because this appears to be the only form of authorization in the HTTP request.

**Finally, let's try to change our role to admin/administrator to gain higher privileges. Unfortunately, without knowing a valid role name, we get Invalid role in the HTTP response, and our role does not update**:

So, all of our attempts appear to have failed. We cannot create or delete users as we cannot change our role. We cannot change our own uid, as there are preventive measures on the back-end that we cannot control, nor can we change another user's details for the same reason. **So, is the web application secure against IDOR attacks?**.

So far, we have only been testing the IDOR Insecure Function Calls. However, we have not tested the API's GET request for IDOR Information Disclosure Vulnerabilities. If there was no robust access control system in place, we might be able to read other users' details, which may help us with the previous attacks we attempted.



# Chaining IDOR vulnerabilities

As mentioned in the previous section, the only form of authorization in our HTTP requests is the role=employee cookie, as the HTTP request does not contain any other form of user-specific authorization, like a JWT token, for example. Even if a token did exist, unless it was being actively compared to the requested object details by a back-end access control system, we may still be able to retrieve other users' details.

As we can see, this returned the details of another user, with their own uuid and role, confirming an IDOR Information Disclosure vulnerability:

```json
{
    "uid": "2",
    "uuid": "4a9bd19b3b8676199592a346051f950c",
    "role": "employee",
    "full_name": "Iona Franklyn",
    "email": "i_franklyn@employees.htb",
    "about": "It takes 20 years to build a reputation and few minutes of cyber-incident to ruin it."
}
```
Now, with the user's uuid at hand, we can change this user's details by sending a PUT request to /profile/api.php/profile/2.
We don't get any access control error messages this time, and when we try to GET the user details again, we see that we did indeed update their details.

In addition to allowing us to view potentially sensitive details, the ability to modify another user's details also enables us to perform several other attacks. 

- One type of attack is modifying a user's email address and then requesting a password reset link, which will be sent to the email address we specified, thus allowing us to take control over their account;
- Another potential attack is placing an XSS payload in the 'about' field, which would get executed once the user visits their Edit profile page, enabling us to attack the user in different ways.

\
\
Since we have identified an IDOR Information Disclosure vulnerability, **we may also enumerate all users and look for other roles, ideally an admin role**. Try to write a script to enumerate all users, similarly to what we did previously.

Once we enumerate all users, we will find an admin user with the following details:

```json
{
    "uid": "X",
    "uuid": "a36fa9e66e85f2dd6f5e13cad45248ae",
    "role": "web_admin",
    "full_name": "administrator",
    "email": "webadmin@employees.htb",
    "about": "HTB{FLAG}"
}
```

We may modify the admin's details and then perform one of the above attacks to take over their account. However, as we now know the admin role name (web_admin), we can set it to our user so we can create new users or delete current users. To do so, we will intercept the request when we click on the Update profile button and change our role to web_admin.

**By combining the information we gained from the IDOR Information Disclosure vulnerability with an IDOR Insecure Function Calls attack on an API endpoint, we could modify other users' details and create/delete users while bypassing various access control checks in place. On many occasions, the information we leak through IDOR vulnerabilities can be utilized in other attacks, like IDOR or XSS, leading to more sophisticated attacks or bypassing existing security mechanisms**.

# IDOR prevention

To prevent such vulnerabilities, we first have to build an object-level access control system and then use secure references for our objects when storing and calling them.

### Object-level access control

An Access Control system should be at the core of any web application since it can affect its entire design and structure. To properly control each area of the web application, its design has to support the segmentation of roles and permissions in a centralized manner. However, Access Control is a vast topic, so we will only focus on its role in IDOR vulnerabilities, represented in Object-Level access control mechanisms.

User roles and permissions are a vital part of any access control system, which is fully realized in a Role-Based Access Control (RBAC) system. To avoid exploiting IDOR vulnerabilities, we must map the RBAC to all objects and resources. **The back-end server can allow or deny every request, depending on whether the requester's role has enough privileges to access the object or the resource**.

Once an RBAC has been implemented, each user would be assigned a role that has certain privileges. Upon every request the user makes, their roles and privileges would be tested to see if they have access to the object they are requesting. They would only be allowed to access it if they have the right to do so.

The following is a sample code of how a web application may compare user roles to objects to allow or deny access control:

```javascript
match /api/profile/{userId} {
    allow read, write: if user.isAuth == true
    && (user.uid == userId || user.roles == 'admin');
}
```

The above example uses the user token, which can be mapped from the HTTP request made to the RBAC to retrieve the user's various roles and privileges. Then, it only allows read/write access if the user's uid in the RBAC system matches the uid in the API endpoint they are requesting. Furthermore, if a user has admin as their role in the back-end RBAC, they are allowed read/write access.

### Object referencing

While the core issue with IDOR lies in broken access control (Insecure), having access to direct references to objects (Direct Object Referencing) makes it possible to enumerate and exploit these access control vulnerabilities. We may still use direct references, but only if we have a solid access control system implemented.

Even after building a solid access control system, we should never use object references in clear text or simple patterns (e.g. uid=1). We should always use strong and unique references, like salted hashes or UUID's. For example, **we can use UUID V4 to generate a strongly randomized id for any element, which looks something like (89c9b29b-d19f-4515-b2dd-abb6e693eb20)**. Then, we can map this UUID to the object it is referencing in the back-end database, and whenever this UUID is called, the back-end database would know which object to return. The following example PHP code shows us how this may work:

```php
$uid = intval($_REQUEST['uid']);
$query = "SELECT url FROM documents where uid=" . $uid;
$result = mysqli_query($conn, $query);
$row = mysqli_fetch_array($result));
echo "<a href='" . $row['url'] . "' target='_blank'></a>";
```

Furthermore, as we have seen previously in the module, we should never calculate hashes on the front-end. **We should generate them when an object is created and store them in the back-end database**. Then, we should create database maps to enable quick cross-referencing of objects and references.

