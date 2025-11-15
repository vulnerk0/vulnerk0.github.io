---
title: HTTP verb tampering
layout: note
toc: true
description: My notes on HTTP verb tamperting
---
# Intro to HTTP Verb Tampering
In HTTP verb tampering we try to request resources on the server using different methods (verbs). The idea is to create edge cases where the developer didn't account for the usage of other methods, let's take an example;
```php
$pattern = "/^[A-Za-z\s]+$/";

if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...SNIP...
}
```
In the above code, we see that the developer is checking the `GET` parameter `code` for bad characters. there is a slight problem here, we don't have to use the `GET` method, if the endpoint  allows the usage of other methods like `POST` we can send a POST request with the body containing the `$_REQUEST["code"]` parameter, which will bypass this filter.
# Bypassing Basic Authentication
Let's say that we have a page protected by an HTTP basic authentication, we can try to access this page with different methods and check the result, let's take an example;
We have a file sharing platform that we can add files to, there are two main functionalities. The add and delete functionalities, if we try to add a file we get a `200` status code and the file is uploaded to the server, however, if we try to delete a file we are asked to authenticate using HTTP basic auth. examining the server requests we see that when we try to delete a file we send a `GET` request to `/delete.php` , we try to change the method to `POST` but to no avail. We try to send a request with the  `HEAD` method and the files get deleted.
## Bypassing Security Filters
Some applications use filters to discard malicious requests, like the code snippet in the intro. We can bypass these filters using other verbs (methods), let's take an example;
The same file sharing platform gets the file name from the user and executes a system command using the `system()` function. before that, it checks the input for any bad characters (used in command injection) like back ticks and semicolons, this is what I imagine the code is like;
```php
$bad_chars = ["$","{","}",";","&","&&","|","`"]
if(preg_match($pattern, $_GET["filename"])) {
	echo "Malicious Input Detected, Discarding Request"
	SNIP...
}
```
The problem is that the server expects the parameter in a GET request, we can change the method to POST and the server will process the file name without applying this filter. After gaining access to the source code, the snippet is close;
```php
if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9. _-]/', $_GET['filename'])) {
        system("touch " . $_REQUEST['filename']);
        header("Refresh:0; url=index.php");
    } else {
        echo "Malicious Request Denied!";
    }
```
But I inverted the process.
# Resources
[OWASP](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering)
