# Command injections characters

| Injection operator | Injection character | URL-encoded character | Executed command|
|--------------------|---------------------|-----------------------|-----------------|
| Semicolon | ; | %3b | Both |
| New line | \n | %0a | Both |
| Background | & | %26 | Both (second output generally shown first) |
| Pipe | \| | %7c | Both (only second output is shown) |
| AND | && | %26%26 | Both (only if first succeeds) |
| OR | \|\| | %7c%7c | Second (only if first fails) |
| Sub-Shell | `` | %60%60 | Both (Linux-only) |
| Sub-Shell	| $() | %24%28%29 | Both (Linux-only) |

We can use any of these operators to inject another command so both or either of the commands get executed. We would write our expected input (e.g., an IP), then use any of the above operators, and then write our new command.

# Bypassing front-end validation
The easiest method to customize the HTTP requests being sent to the back-end server is to use a web proxy that can intercept the HTTP requests being sent by the application. To do so, we can start Burp Suite or ZAP and configure Firefox to proxy the traffic through them. Then, we can enable the proxy intercept feature, send a standard request from the web application with any IP (e.g. 127.0.0.1), and send the intercepted HTTP request to repeater by clicking [CTRL + R], and we should have the HTTP request for customization.


# Filter/WAF detection


### Blacklisted characters
A web application may have a list of blacklisted characters, and if the command contains them, it would deny the request. The PHP code may look something like the following:

```php
$blacklist = ['&', '|', ';', ...SNIP...];
foreach ($blacklist as $character) {
    if (strpos($_POST['ip'], $character) !== false) {
        echo "Invalid input";
    }
}
```
If any character in the string we sent matches a character in the blacklist, our request is denied. Before we start our attempts at bypassing the filter, we should try to identify which character caused the denied request.

### Blacklisted spaces

- To bypass the blacklisted spaces we can use the **"tabs" (%09)**;
- In Linux, we can use the \$IFS Linux Environment Variable. So, if we use **\${IFS}** where the spaces should be, the variable should be automatically replaced with a space, and our command should work;
- There are many other methods we can utilize to bypass space filters. For example, we can use the **Bash Brace Expansion feature, which automatically adds spaces between arguments wrapped between braces**. 

### Blaclisted \/ or \\ (slash and backslash characters)

In Linux we can replace "/" using environment variables. We can put this char in an environment variable and then specify **start** and **length** of our string to exactly match this char. For example we can use the $PATH variable which is something like this:
- /usr/local/bin:/usr/bin:/bin:/usr/games

So, if we start at the 0 character, and only take a string of length 1, we will end up with only the / character:
- echo ${PATH:0:1}

We can do the same thing for the semicolumn:
- echo ${LS_COLORS:10:1}


In Windows we can do the same. For example, to produce a slash in Windows Command Line (CMD), we can echo a Windows variable (%HOMEPATH% -> \Users\htb-student), and then specify a starting position (~6 -> \htb-student), and finally specifying a negative end position, which in this case is the length of the username htb-student (-11 -> \):
- echo %HOMEPATH:~6,-11%

We can achieve the same thing using the same variables in **Windows PowerShell**. With PowerShell, a word is considered an array, so we have to specify the index of the character we need. As we only need one character, we don't have to specify the start and end positions:
- $env:HOMEPATH[0]

We can also use the **Get-ChildItem Env**: PowerShell command to print all environment variables and then pick one of them to produce a character we need.

### Character shifting

There are other techniques to produce the required characters without using them, like shifting characters. For example, the following Linux command shifts the character we pass by 1. So, all we have to do is find the character in the ASCII table that is just before our needed character (we can get it with man ascii), then add it instead of \[ in the below example. This way, the last printed character would be the one we need:
- man ascii     # \ is on 92, before it is \[ on 91;
- echo $(tr '!-\}' '"-~'<<<\[).


# Bypass blacklisted commands

We have discussed various methods for bypassing single-character filters. However, there are different methods when it comes to bypassing blacklisted commands. A command blacklist usually consists of a set of words, and if we can obfuscate our commands and make them look different, we may be able to bypass the filters.

- Example: a command like "whoami" could be blacklisted.

A basic command blacklist filter in PHP would look like the following:

```bash
$blacklist = ['whoami', 'cat', ...SNIP...];
foreach ($blacklist as $word) {
    if (strpos('$_POST['ip']', $word) !== false) {
        echo "Invalid input";
    }
}
```

However, this code is looking for an exact match of the provided command, so if we send a slightly different command, it may not get blocked. Luckily, we can utilize various obfuscation techniques that will execute our command without using the exact command word.

One very common and easy obfuscation technique is **inserting certain characters within our command that are usually ignored by command shells like Bash or PowerShell** and will execute the same command as if they were not there. Some of these characters are a single-quote ' and a double-quote ", in addition to a few others.

The easiest to use are quotes, and they work on both Linux and Windows servers. For example, if we want to obfuscate the whoami command, we can insert single quotes between its characters, as follows:

```w'h'o'am'i```

The same works with double-quotes as well:
```w'h'o'am'i```

N.B.: we cannot mix types of quotes and the number of quotes must be even.

### Commands bypass Linux only

We can insert a few other Linux-only characters in the middle of commands, and the bash shell would ignore them and execute the command. These characters include **the backslash \\** and the **positional parameter character \$@**. This works exactly as it did with the quotes, but in this case, the number of characters do not have to be even, and we can insert just one of them if we want to:
```who$@ami```

### Commands bypass Windows only

There are also some Windows-only characters we can insert in the middle of commands that do not affect the outcome, like a caret (^) character, as we can see in the following example:
```who^ami```


# Advanced command obfuscation

### Case manipulation

One command obfuscation technique we can use is case manipulation, like inverting the character cases of a command **(e.g. WHOAMI)** or alternating between cases **(e.g. WhOaMi)**.
This usually works because a command blacklist may not check for different case variations of a single word, as Linux systems are case-sensitive.
If we **are dealing with a Windows server**, we can change the casing of the characters of the command and send it. In Windows, commands for PowerShell and CMD are **case-insensitive**, meaning they will execute the command regardless of what case it is written in.

However, when it comes to **Linux and a bash shell**, which are case-sensitive, as mentioned earlier, we have to get a bit creative and find a command that turns the command into an all-lowercase word. One working command we can use is the following:
```$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")```

As we can see, the command did work, even though the word we provided was (WhOaMi). This command uses tr to replace all upper-case characters with lower-case characters, which results in an all lower-case character command.

### Reversed commands

Another command obfuscation technique we will discuss is reversing commands and having a command template that switches them back and executes them in real-time. In this case, we will be writing **imaohw instead of whoami** to avoid triggering the blacklisted command.

We can get creative with such techniques and create our own Linux/Windows commands that eventually execute the command without ever containing the actual command words. First, we'd have to get the reversed string of our command in our terminal, as follows:

```echo 'whoami' | rev```

Then, we can execute the original command by reversing it back in a sub-shell ($()), as follows:

```$(rev<<<'imaohw')```

The same can be applied in **Windows**. We can first reverse a string, as follows:
```$("whoami"[-1..-20] -join ''```

We can now use the below command to execute a reversed string with a PowerShell sub-shell (iex "$()"), as follows:

```iex "$('imaohw'[-1..-20] -join '')"```

### Encoded commands

The final technique we will discuss is helpful for commands containing filtered characters or characters that may be URL-decoded by the server. This may allow for the command to get messed up by the time it reaches the shell and eventually fails to execute. Instead of copying an existing command online, we will try to create our own unique obfuscation command this time. This way, it is much less likely to be denied by a filter or a WAF. The command we create will be unique to each case, depending on what characters are allowed and the level of security on the server.

We can utilize various encoding tools, **like base64 (for b64 encoding) or xxd (for hex encoding)**. Let's take base64 as an example. First, we'll encode the payload we want to execute (which includes filtered characters):

```echo -n 'cat /etc/passwd | grep 33' | base64```

Now we can create a command that will decode the encoded string in a sub-shell ($()), and then pass it to bash to be executed (i.e. bash<<<), as follows:

```bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)```


We use the same technique with **Windows** as well. First, we need to base64 encode our string, as follows:

```[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))```

Finally, we can decode the b64 string and execute it with a PowerShell sub-shell (iex "$()"), as follows:

```iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"```


# Evasion tools

### Bashfuscator (Linux)
We can start by simply providing the command we want to obfuscate with the -c flag:

```./bashfuscator -c 'cat /etc/passwd'```

However, running the tool this way will randomly pick an obfuscation technique, which can output a command length ranging from a few hundred characters to over a million characters! So, we can use some of the flags from the help menu to produce a shorter and simpler obfuscated command, as follows:

```./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1```

We can now test the outputted command with **bash -c ''**, to see whether it does execute the intended command:

```bash -c 'eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"'```


### DOSfuscation (Windows)

There is also a very similar tool that we can use for Windows called DOSfuscation. Unlike Bashfuscator, this is an interactive tool, as we run it once and interact with it to get the desired obfuscated command. We can once again clone the tool from GitHub and then invoke it through PowerShell.

```powershell
SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
encoding
1
```

Finally, we can try running the obfuscated command on CMD, and we see that it indeed works as expected:

```
typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt
```