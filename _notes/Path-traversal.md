---
title: Path traversal
description: My notes on path traversal
---
# Overview
This vulnerability arises when the application fetches a file from the system using a parameter that the user can change.

### scenarios of path traversal
#### Standard 
This is the most basic one with no filters. All you need to do is go up in the directory and provide the full path of the file you want - /etc/passwd  for example -.
#### Absolute path
If the application does some filtering on the ../ sequence, you can try using the absolute path of the file without the directory traversal sequence. You can guess the behavior of the server by examining the source code and checking the src of the images loaded.
#### Basic stripping
Some times the developer is smart, and will implement some kind of filtering. maybe the application checks the file path and if any LFI sequence found will be stripped. For example `../../../etc/passwd` will go to the back end like `/etc/passwd`, in this case try embedding the sequences into each other like `....//` or `....\/`. The application will see `../` and will remove it, if you sent `....//....//....//etc/passwd` the back-end will receive `../../../etc/passwd`.
#### Encoding
If the application might strip the the LFI sequence. Another bypass to this is encoding, you can try URL encoding and double or triple encoding.
#### Path validation
some times the application does some kind of path validation to ensure the integrity  of the file specified. For example; the application checks if the filepath starts with /var/www/images/ , you can bypass this check by appending the payload after the base path like this `/var/www/images/../../../etc/passwd`.
#### Extension validation
This time the application checks the extension of the file, if it matches whats in the white list, the application will fetch the resource. You can bypass this restriction by using the null byte, pass the desired file with a trailing null byte and an extension like so `../../../etc/passwd%00.png`

### Labs
You can find a lab for each of the scenarios on [Portswigger](https://portswigger.net/web-security/file-path-traversal)<br>
Also check [Owasp](https://owasp.org/www-community/attacks/Path_Traversal)

## Notes
- some times you will find the parameter responsible for fetching the file in the page source, fetching js files and images. 