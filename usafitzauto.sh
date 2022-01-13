#!/bin/bash

DAY=$(date +%u)
DATE=$(date +%Y%b%d-%T)

echo "Begin Program: $DATE"

nmapon=1
dirbon=1
exitoption=0

read -p "Which IP or NETWORK [10.11.1.0/24]:  " ip
echo "  "

function quit {
	exit
}

# NMAP FUNCTION SECTION

function nmap_setup { # CREATE FOLDER / CALL COMMANDS
    DATENMAP=$(date +%Y%b%d-%T) 
    # echo " within nmap_setup: $DATENMAP"
    mkdir ./output_files/nmap
    mkdir ./output_files/nmap/$DATENMAP
    mkdir ./output_files/nmap/$DATENMAP/common
    mkdir ./output_files/nmap/$DATENMAP/nse

}

function nmap_find_hosts { # SCAN NETWORK FOR HOSTS THAT ARE UP
    # echo "wintin nmap_sn: $DATENMAP"
	echo "  "
	echo "==================="
	echo "=== HOSTS FOUND ==="
	echo "==================="
	nmap -sn $ip | grep "report for" | cut -d " " -f 5 >> ./output_files/nmap/$DATENMAP/hostsup.txt
	cat ./output_files/nmap/$DATENMAP/hostsup.txt
	#nmap -sn $1 -oG nmap_$1_fullrange
	echo "==================="
}

function nmap_common { # TCP SYN SCAN (REQUIRES SUDO | QUICK AND EASY)
    for host_ip in $(cat ./output_files/nmap/$DATENMAP/hostsup.txt)
        do
            echo "  "
            echo "STARTING COMMON NMAP OF:  $host_ip"
            sudo nmap -A -sS $host_ip >> ./output_files/nmap/$DATENMAP/common/$host_ip.txt
            echo "  "
            cat ./output_files/nmap/$DATENMAP/common/$host_ip.txt

            if [[ $(cat ./output_files/$DATENMAP/common/$host_ip.txt | grep "Windows") == *"Windows"* || *"Microsoft"* ]] 
                then
                    mv ./output_files/nmap/$DATENMAP/common/$host_ip.txt ./output_files/nmap/$DATENMAP/common/$host_ip\_Windows.txt
            fi
            echo "  "
            echo "HOST: " $host_ip " COMPLETE -- VIEW FILES IN: ./output_files/nmap/$DATENMAP/common/"
        done
}

function nmap_nse { # NMAP SCRIPTING ENGINE (NSE)
    for host_ip in $(cat ./output_files/nmap/$DATENMAP/hostsup.txt)
        do
            echo "  "
            echo "STARTING NMAP SCRIPT ENGINE SCAN OF:  $host_ip"
            nmap -sV -vv --script vuln $host_ip >> ./output_files/nmap/$DATENMAP/nse/$host_ip.txt
            echo "  "
            cat ./output_files/nmap/$DATENMAP/nse/$host_ip.txt

            if [[ $(cat ./output_files/$DATENMAP/nse/$host_ip.txt | grep "Windows") == *"Windows"* || *"Microsoft"* ]] 
                then
                    mv ./output_files/nmap/$DATENMAP/nse/$host_ip.txt ./output_files/nmap/$DATENMAP/nse/$host_ip\_Windows.txt
            fi
            echo "  "
            echo "HOST: " $host_ip " COMPLETE -- VIEW FILES IN: ./output_files/nmap/$DATENMAP/nse/"
        done
	
    # nmap -sL -oG - -iR 5 $ip
}

while [ $exitoption = 0 ]
    do
        # RESET ALL THE TOOLS TO ON (AVAILABLE)
        nmapon=1
        dirbon=1
        gobusteron=1
        niktoon=1
        enum4linuxon=1
        nbtscanon=1
        snmpwalkon=1
        showounton=1
        hydraon=1
        # TOOLS
        # Great source for info:  https://hausec.com/pentesting-cheatsheet/#_Toc475368977
        # list of kali installed tools: https://www.kali.org/tools/
        echo "  "
        echo "-- ENTER YOUR SELECTION --"
        echo "0 EXIT PROGRAM "
        echo "1 NMAP " 
        # scans a network or target for open ports and vulnerabilities
        echo "2 DIRB "
        # scans a target for directories or types of files in a specified wordlist
        echo "3 GOBUSTER "
        # Scan a website (-u http://192.168.0.155/) for directories using a wordlist (-w)
        echo "4 NIKTO (very noisy) "
        # Nikto is not designed as a stealthy tool. It will test a web server in the quickest time possible, and is obvious in log files or to an IPS/IDS.
        echo "5 ENUM4LINUX"
        # Enum4linux is a tool for enumerating information from Windows and Samba systems.
        # Attempt to get the userlist (-U) and OS information (-o) from the target (192.168.1.200):
        echo "6 NBTSCAN "
        # NBTscan is a program for scanning IP networks for NetBIOS name information. 
        echo "7 SNMPWALK "
        #an SNMP application that uses SNMP GETNEXT requests to query a network entity for a tree of information.
        echo "8 SHOWMOUNT "
        # queries the mount daemon on a remote host for information about the state of the NFS server on that machine. 
        echo "9 HYDRA "
        # brute force attempts to log into a remote system
        echo "99 ADMIN MENU "
        # this is for use of listening and serving tools, such as netcat and SimpleHTTPServer
        echo "       "
        read -p "TOOL SELECTION: " tool

        if [[ $tool = 0 ]] # EXIT PROGRAM
            then
                quit
        elif [[ $tool = 1 ]] # NMAP
            then
                nmap_setup
                echo "  "
                echo "-- NMAP --"
                echo "  "
                while [ $nmapon = 1 ] # RUN NMAP UNTIL QUIT
                    do 
                        echo "Which type of scan would you like?"
                        echo "0 Back to main menu "
                        echo "1 Common & Popular "
                        echo "2 High Enumeration "
                        echo "3 Run All Scans (overnight) "
                        echo "  "
                        read -p "YOUR SELECTION:  " namppreference
                        echo "  "
                            if [[ $namppreference = 0 ]] # COMMON NMAP SCAN
                                then
                                    nmapon=0
                            elif [[ $namppreference = 1 ]] # COMMON NMAP SCAN
                                then
                                    nmap_find_hosts
                                    nmap_common
                                    nmapon=0
                            elif [[ $namppreference = 2 ]] # VULNERABILITY NMAP SCAN
                                then
                                    nmap_find_hosts
                                    nmap_nse
                                    nmapon=0
                            elif [[ $namppreference = 3 ]] # VULNERABILITY NMAP SCAN
                                then
                                    nmap_find_hosts
                                    nmap_common
                                    nmap_nse
                                    nmapon=0        
                            else
                                echo "... not an option"
                                echo "exiting NMAP ..."
                                nmapon=0
                            fi  
                    echo "  " 
                    done
                echo "  "
                echo "Exiting NMAP..."
        elif [[ $tool = 2 ]] # DIRB
            then
                echo "Coming Soon..."
        elif [[ $tool = 3 ]] # GOBUSTER
            then
                echo "Coming Soon..."
        elif [[ $tool = 4 ]] # NIKTO
            then
                echo "Coming Soon..."
        elif [[ $tool = 5 ]] # ENUM4LINUX
            then
                echo "Coming Soon..."
        elif [[ $tool = 6 ]] # NBTSCAN
            then
                echo "Coming Soon..."
        elif [[ $tool = 7 ]] # SNMPWALK
            then
                echo "Coming Soon..."
        elif [[ $tool = 8 ]] # SHOWMOUNT
            then
                echo "Coming Soon..."
        elif [[ $tool = 9 ]] # HYDRA
            then
                echo "Coming Soon..."
        elif [[ $tool = 99 ]] # ADMIN MENU - this is for use of listening and serving tools, such as netcat and SimpleHTTPServer

            then
                echo "Coming Soon..."
        else 
           echo "Plesae enter a valid option... "
           echo "  "
        fi
    done

# # CREATE FRESH DIRECTORY FOR ALL OUTPUT FILES
# mkdir ./output_files/nmap/$DATE 

# # DO AN INITIAL SCAN TO SEE WHICH IP IS AVAILABLE
# nmap_sn $ip

# # USE THE CREATED LIST TO SCAN INDIVIDUAL COMPUTERS
# for host_ip in $(cat ./output_files/nmap/$DATE/hostsup_$DATE.txt)
# do
# 	nmap_command $host_ip

#     echo "HOST: " $host_ip " COMPLETE -- VIEW FILES IN: ./output_files/nmap/$DATE"

#     if [[ $(cat ./output_files/$DATE/$host_ip.txt | grep "Windows") == *"Windows"* ]] 
#     then
#         mv ./output_files/nmap/$DATE/$host_ip.txt ./output_files/nmap/$DATE/$host_ip\_Windows.txt
#     fi
# done

# DIRB FUNCTION SECTION




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
