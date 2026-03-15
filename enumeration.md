# Enumeration

## Nmap
```shell
nmap -sV -Pn -A $IP
```
-sV   # Service and version detection
-A    # Aggressive mode (e.g. OS detection)
-Pn   # Skip host discovery

## Gobuster

### File discovery
```shell
gobuster dir -u $IP -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -b 403,404 -x php,html,txt,js
```

### Endpoint discovery
```shell
gobuster dir -u $IP -w /usr/share/seclists/Discovery /Web-Content/raft-large-directories.txt -x php,html,txt,js
```

## Wfuzz

### Parameter discovery
```shell
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt --hc 404,301 "$IP/FUZZ=data"
```

### GET parameter values
```shell
wfuzz -c -z file,/usr/share/seclists/Usernames/cirt-default-usernames.txt --hc 404,301 "$IP/index.php?parameter=FUZZ"
```