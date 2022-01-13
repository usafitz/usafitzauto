#!/bin/bash

DAY=$(date +%u)
DATE=$(date +%Y%b%d-%T)

read -p "Which IP or NETWORK [10.11.1.0/24]:  " ip
echo "  "

function quit {
	exit
}

function changefilename {
    echo "  "
}

function nmap_sn { # SCAN NETWORK FOR HOSTS THAT ARE UP
	echo "  "
	echo "==================="
	echo "=== HOSTS FOUND ==="
	echo "==================="
	nmap -sn $ip | grep "report for" | cut -d " " -f 5 >> ./output_files/$DATE/hostsup_$DATE.txt
	cat ./output_files/$DATE/hostsup_$DATE.txt
	#nmap -sn $1 -oG nmap_$1_fullrange
	echo "==================="
}

function nmap_sl { # FUTURE POSSIBILITIES
	nmap -sL -oG - -iR 5 $ip
}

function nmap_command { # TCP SYN SCAN (REQUIRES SUDO | QUICK AND EASY)
    # REMOVED -oG
    echo "  "
    echo "BEGIN: nmap -A -sS $1"
	sudo nmap -A -sS $1 >> ./output_files/$DATE/$1.txt
    echo "  "
}

# CREATE FRESH DIRECTORY FOR ALL OUTPUT FILES
mkdir ./output_files/$DATE 

# DO AN INITIAL SCAN TO SEE WHICH IP IS AVAILABLE
nmap_sn $ip

# USE THE CREATED LIST TO SCAN INDIVIDUAL COMPUTERS
for host_ip in $(cat ./output_files/$DATE/hostsup_$DATE.txt)
do
	nmap_command $host_ip

    echo "HOST: " $host_ip " COMPLETE -- VIEW FILE AT: ./output_files/$DATE/$host_ip.txt"

    if [[ $(cat ./output_files/$DATE/$host_ip.txt | grep "Windows") == *"Windows"* ]] 
    then
        mv ./output_files/$DATE/$host_ip.txt ./output_files/$DATE/$host_ip\_Windows.txt
    fi
    # cat output_files/$DATE/$1 | grep "Windows" 

    echo "  "
    string='My long string'
    if [[ $string == *"My long"* ]]; then
        echo "It's there!"
    fi
    # cat output_files/$DATE/$1 | grep "Windows"
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
