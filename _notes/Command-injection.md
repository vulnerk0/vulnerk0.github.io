---
title: Command injection
description: My notes about command injection
---
# Overview
Also known as shell injection, your goal is to pass system commands to the underlying system. if you are in a black box scenario, any parameter might be vulnerable because the application might issue system commands with the HTTP parameters as arguments to the command.

## Scenario 1 - simple
some functionality on the website might be coded to perform system commands. For example, you want to fetch the stock for a product, so the application takes the product id and issues a system command like './check_stock.sh \<product-id\>' you can try to change the product id to something like &sleep 5& and check the result. I used sleep to make sure I have control over the sever because I might not be able to see the output of the command, but in this case I can see the output by using URL-encoded & command separator.

### Labs
[os command injection, simple case](https://portswigger.net/web-security/os-command-injection/lab-simple)

## Scenario 2 - blind
most of the os command injection vulnerabilities do not return an output, you can use the above mentioned technique to confirm that you indeed have command injection capabilities. If you want to see the output you  can redirect the output of the command to a directory that you can access via the web (i.e. /uploads under /var/www/html/uploads), using the greater than operand > lets you redirect output to a desired file. 

## callback
You can also use the "callback" method which works on alot of vulnerabilities, when you use this method you want the server to send any message to you, it might be a dns lookup on a domain you own or an email or a get request to your server. In the context of command injection you can use `nslookup` to send a message to your domain - which could be a burp collaborator server - or use `curl` to send an HTTP request to your server -if don't own the domain like ngrok-.

### Labs
[Blind os command injection with time delays](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)<br>
[Blind os command injection with output redirection](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)<br>
[Blind os command injection with out-of-band interaction](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band)

## Other ways of injection
Don't forget that the command you want to execute is initially part of a bigger command, so you want to either use inline command execution or use command separators so that the main command will execute, then yours. These are command separators on both unix and windows  systems:
- &
- &&
- \|
- \|\|

These only work for Linux:
- ;
- \n or 0x0a (for newline, its like hitting the enter button)

As for inline command execution you can use these for Unix systems:
- \`whoami\` notice the back-ticks
- $(whoami)

Some times the command executed will be like:
`./fetch_info.sh "productid"`
notice that the product id is within a quotation, you need to escape it like:
`./fetch_info.sh ""&whoami&""`
in this example you will send ("&whoami&") to the server.

## Side notes
- I noticed that the command separators will behave differently. For example, sometimes the & separator will give you output, unlike the back-tick which will not return output.
- You might need to URL-encode the command separators.
- Don't test for command injection in the terminal. 99% of the time you will execute command on your machine and think it's the target server (especially with sleep).
- if the application uses black-listing or escaping the command separators that this is 100% bypassable.
## Resources
[Owasp](https://owasp.org/www-community/attacks/Command_Injection)<br>
[Portswigger](https://portswigger.net/web-security/os-command-injection)
