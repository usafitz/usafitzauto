#!/bin/bash

DAY=$(date +%u)
DATE=$(date +%Y%b%d-%T)

read -p "Which IP Address?  " ip
echo "  "

function quit {
	exit
}

function nmap_sn {
	echo "  "
	echo "==================="
	echo "=== HOSTS FOUND ==="
	echo "==================="
	nmap -sn $ip | grep "report for" | cut -d " " -f 5 >> hostsup_$DATE.txt
	cat hostsup_$DATE.txt
	#nmap -sn $1 -oG nmap_$1_fullrange
	echo "==================="
}

function nmap_sl {
	nmap -sL -oG - -iR 5 $ip
}

function nmap_command {
	sudo nmap -sS $1 -oG $1
}

nmap_sn $ip

for p in $(cat hostsup_$DATE.txt)
do
	nmap_command $p
done

#read -p "Which IP or Network?:  " ip
#echo "  "
#
#echo "-- NMAP --"
#echo "1. Scan Network for hosts"
#echo "2. Stealth Scan"
#echo "  "
#echo "-------------------------"
#read -p "SELECTION:  " selection
#
#nmap -sn 10.11.1.0/24 | grep "report for" | cut -d " " -f 5
#
#for ip in $(seq 1 254)
#	do nmap_sn 10.11.1.$ip
#done

quit
