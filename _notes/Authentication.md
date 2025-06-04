---
title: Authentication
description: My notes on authentication vulnerabilities
---
# Overview
Authentication is the process of identifying the identity of the person, the server wants to make sure that the user is indeed who he is claiming to be.

## Types of authentication vulnerabilities

#### Vulnerabilities in password-based login
We are mainly talking about brute forcing because we don't have much flexibility. If you are working with a website that uses password based login ONLY you can try to enumerate usernames, and this can be done by observing multiple factors such as:
- Status code
- Error messages - like the default ones in WordPress - 
- Response times
- IP block
	Check the response for a valid username and an invalid username and notice any differences.
	
	Check the status code for a valid username and an invalid username and check for differences.
	
	Provide a valid username with a very long password and write down the time, then try to enumerate other usernames with the same method, if the username is incorrect the RT should be low, and if the .
	
	If you are being blocked after a certain number of times, try logging in before the last attempt and check if the times has been reset
	
	You can try sending invalid passwords to a number of usernames, if a user account get locked, than that's a valid username - this method require the account lock mechanism-
#### mass assignment
Try providing an array of password values instead of a single password, you can also use the mass assignment method found in GraphQl APIs

#### multi-factor Authentication
Thus far I've talked about the password authentication mechanisms, but more website these days use what's called a "multi-factor Authentication". These are some of the things to check for when testing 2FA:
	After logging in and before providing the code sent to your email, try going to the dashboard page to see if you can skip the code step 
	Check the logic of the application. after logging in, you might be able to enter the verification code as another user.

#### Other auth mechanisms
:
	Always check the cookies that you get when logged in, some of them might contain information about the account. You can use this information to predict other cookie values that my lead you to taking over other accounts
#### Host poisoning
Some times when initiating a reset password link, the web server will take the domain name from the Host header. if this is the case you can change the host header to any domain you own - like ngrok -, and send the request, when you receive the email you might notice that the domain is yours. Also try other headers like X-Forwarded-Host.
#### Password change 
Most websites have a password change functionality. the most common structure is current password then new password two times, try putting different new passwords and provide an invalid current password and check the output, some times an error will occur saying that the current password is incorrect. Now enter a valid current password and check the output, if the error message changes to something like "new passwords do not match" then you have a vulnerability, in this way you can bypass the rate-limit on the login form and brute force the password for a target.

### Recources
Check [Portswigger](https://portswigger.net/web-security/authentication)