---
title: SSRF
description: My notes on server-side request forgery
---

# Overview
The SSRF vulnerability arises when the application sends an HTTP request containing a URL that fetches a resource. You can try to change this URL and point it to your own domain, if you receive a request from the server than you have a vulnerable parameter. You can try to access the internal resources thru "localhost" or pivot into the network.

## Hidden Attack surfaces
Other than the obvious request_uri parameter that you might find on a website, sometimes the vulnerability is hidden with in the application. That's why you need to understand the application before testing for any vulnerabilities, I'll list some of them:

You might see in the front-end that the application sends a request to a path - in the body
or a parameter or a header- but the back-end the server adds a url and sends a request. Let's take an example:
In the front-end the request is as follows:
```
GET / HTTP/2
Host: example.com
Content-Type: application/x-www-form-urlencoded

checkuser=/users/usercheck?id=2 <YOU CONTROL THIS>
```
and the back end issues this request:
```
GET / HTTP/2
Host: example.com
Content-Type: application/x-www-form-urlencoded

checkuser=http://internaldomain/users/usercheck?id=2
```
In this case I would try adding @ in the beginning of the path so the request would be:
```
checkuser=@myowndomain
```
and the back-end request will be:
```
checkuser=http://internaldomain@myowndomain
```
adding @ before my domain makes the back-end think that `internaldomain` is some sort of credentials because you can provide credentials in the url using the @ character:
`http://username:password@localdomain.com`.

Try changing the value of the referer header and check the result.

--- 
## Techniques
These are some of the techniques I found online: - You can user the interactsh tool and get a domain for testing, because some of these techniques are for blind SSRF -: 
- Change the host header to `Host: internalip:80` (Advanced and more powerful)
- Use the Unicode characters like ①②⑦.①
- You can try `GET http://internalip` or `GET http://privatedomain` also try without the scheme.
- provide the internal IP to these headers [Check this blog](https://requestly.com/blog/what-are-x-forwarded-headers-and-why-it-is-used/): 
	- X-Forwarded-For
	- True-Client-IP
	- X-Real-IP
	- Referer
## Recources
If you want a full recap, check [Portswigger](https://portswigger.net/web-security/ssrf)