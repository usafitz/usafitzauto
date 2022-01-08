#!/bin/bash

DAY=$(date +%u)
DATE=$(date +%Y%b%d-%T)
nmapon=1
dirbon=1
exitoption=0

read -p "Which IP Address?  " ip
echo "  "

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
        echo "--ENTER YOUR SELECTION--"
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

        if [[ $tool = 0 ]] # NMAP
            then
                exitoption=1
        elif [[ $tool = 1 ]] # NMAP
            then
                echo "You have selected to use NMAP"
                echo "  "
                while [ $nmapon = 1 ] # RUN NMAP UNTIL QUIT
                    do 
                        echo "Which type of scan would you like?"
                        echo "0 Back to main menu "
                        echo "1 Common & Popular "
                        echo "2 High Enumeration "
                        echo "  "
                        read -p "YOUR SELECTION:  " namppreference
                        echo "  "
                            if [[ $namppreference = 0 ]] # COMMON NMAP SCAN
                                then
                                    nmapon=0
                            elif [[ $namppreference = 1 ]] # COMMON NMAP SCAN
                                then
                                    echo "BEGIN COMMON NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
                                    echo "  "
                                    nmap -A -T4 -p- -oN output_files/nmap_$ip\_$DATE.txt $ip
                                    echo "  "
                                    echo "END COMMON NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
                                    echo "  "
                                    nmapon=0
                            elif [[ $namppreference = 2 ]] # VULNERABILITY NMAP SCAN
                                then
                                    echo "BEGIN VULN NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
                                    nmap -sV -vv --script vuln -oN output_files/nmap_vuln_$ip\_$DATE.txt $ip
                                    echo "  "
                                    echo "END VULN NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
                                    echo "  "
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
        elif [[ $tool = 2 ]]  # DIRB
            then
                echo "You have selected to use DIRB"
                echo "  "
                while [ $dirbon = 1 ] # RUN DIRB UNTIL QUIT
                    do
                        echo "Do you have a specific wordfile to use?"
                        echo "Which type of scan would you like?"
                        echo "0 Back to main menu "
                        echo "1 Specify your own wordlist "
                        echo "2 Default scan (quickest)"
                        echo "3 Massive wordlist scan (long duration) "
                        echo "  "
                        read -p "YOUR SELECTION:  " dirbpreference
                            if [[ $dirbpreference = 0 ]] # EXIT DIRB
                                then
                                    dirbon=0
                            elif [[ $dirbpreference = 1 ]] # SPECIFIC WORDFILE ENTRY AND RUN
                                then
                                    read -p "Please specfiy absolute location and file:  "  wordfile
                                    echo "  " 
                                    echo "BEGIN DIRB SCAN OF $ip -- {[$DAY] - $DATE}"
                                    echo "DEFAULT:  dirb http://$ip $wordfile -w -o output_files/dirb_$ip\_$DATE.txt"
                                    echo "  "
                                    echo "Other options include:  "
                                    echo "-W EXTENSIONS_LIST: (.php) | (.php) [NUM = 1]"
                                    echo "-H ADDED HEADERS (LIKE .php)"
                                    echo "-r OPTION: Not Recursive"
                                    echo "-z SPEED_DELAY: 100 milliseconds"
                                    echo "-v OPTION: Show Not Existent Pages"
                                    echo "-N OPTION: Ignoring NOT_FOUND code -> 302"
                                    echo "-w OPTION: Not Stopping on warning messages"
                                    echo "-u admin:admin AUTHORIZATION: admin:admin (authentication)"
                                    echo "-p PROXY: localhost:8080"
                                    echo "  "
                                    echo "  "
                                    dirb http://$ip $wordfile -w -o output_files/dirb_$ip\_$DATE.txt
                                    echo " "
                                    echo "END DIRB SCAN OF $ip -- {[$DAY] - $DATE}"
                                    echo " "
                                    dirbon=0
                            elif [[ $dirbpreference = 2 ]] # DEFAULT DIRB
                                then
                                    echo "  " 
                                    echo "BEGIN DIRB SCAN OF $ip -- {[$DAY] - $DATE}"
                                    echo "DEFAULT:  http://$ip files/dirb/common.txt -w -o output_files/dirb_$ip\_$DATE.txt"
                                    echo "  "
                                    echo "Other options include:  "
                                    echo "-W EXTENSIONS_LIST: (.php) | (.php) [NUM = 1]"
                                    echo "-H ADDED HEADERS (LIKE .php)"
                                    echo "-r OPTION: Not Recursive"
                                    echo "-z SPEED_DELAY: 100 milliseconds"
                                    echo "-v OPTION: Show Not Existent Pages"
                                    echo "-N OPTION: Ignoring NOT_FOUND code -> 302"
                                    echo "-w OPTION: Not Stopping on warning messages"
                                    echo "-u admin:admin AUTHORIZATION: admin:admin (authentication)"
                                    echo "-p PROXY: localhost:8080"
                                    echo "  "
                                    echo "  " 
                                    dirb http://$ip files/dirb/common.txt -w -o output_files/dirb_$ip\_$DATE.txt
                                    echo " "
                                    echo "END DIRB SCAN OF $ip -- {[$DAY] - $DATE}"
                                    echo "  "
                                    dirbon=0
                            elif [[ $dirbpreference = 3 ]] # MASSIVE WORDLIST SCAN
                                then
                                    echo "  "
                                    echo "BEGIN DIRB SCAN OF $ip -- {[$DAY] - $DATE}"
                                    echo "DEFAULT:  dirb http://$ip files/dirb/*.txt -w -o output_files/dirb_massive_$ip\_$DATE.txt"
                                    echo "  "
                                    echo "Other options include:  "
                                    echo "-W EXTENSIONS_LIST: (.php) | (.php) [NUM = 1]"
                                    echo "-H ADDED HEADERS (LIKE .php)"
                                    echo "-r OPTION: Not Recursive"
                                    echo "-z SPEED_DELAY: 100 milliseconds"
                                    echo "-v OPTION: Show Not Existent Pages"
                                    echo "-N OPTION: Ignoring NOT_FOUND code -> 302"
                                    echo "-w OPTION: Not Stopping on warning messages"
                                    echo "-u admin:admin AUTHORIZATION: admin:admin (authentication)"
                                    echo "-p PROXY: localhost:8080"
                                    echo "  "
                                    echo "  " 
                                    dirb http://$ip files/dirb/*.txt -w -o output_files/dirb_massive_$ip\_$DATE.txt
                                    dirbon=0
                            else
                                echo "... not an option"
                                echo "exiting DIRB ..."
                                dirbon=0
                            fi
                    done
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
        elif [[ $tool = 99 ]] # ADMIN MENU
            then
                echo "Coming Soon..."
        else 
           echo "Plesae enter a valid option... "
           echo "  "
        fi
    done