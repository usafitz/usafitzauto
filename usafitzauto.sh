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
        # TOOLS
        echo "  "
        echo "--ENTER YOUR SELECTION--"
        echo "0 EXIT PROGRAM "
        echo "1 NMAP " 
        echo "2 DIRB "
        echo "3 GOBUSTER "
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
                        echo "1 Common & Popular"
                        echo "2 High Enumeration"
                        echo "  "
                        read -p "YOUR SELECTION:  " namppreference
                        echo "  "
                            if [[ $namppreference = 1 ]] # COMMON NMAP SCAN
                                then
                                    echo "BEGIN COMMON NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
                                    echo "  "
                                    nmap -A -T4 -p- -oN output_files/nmap_$ip\_$DATE.txt $ip
                                    echo "  "
                                    echo "END COMMON NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
                                    echo "  "
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
                        read -p "Would you like to run a vulnerability NMAP scan? [y/n]:  " runanswer
                            if [ $runanswer = y ] # RUN NMAP AGAIN
                                then
                                    echo "BEGIN VULN NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
                                    nmap -sV -vv --script vuln -oN output_files/nmap_vuln_$ip\_$DATE.txt $ip
                                    echo "  "
                                    echo "END VULN NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
                                    echo "  "
                                    nmapon=0
                            elif [ $runanswer = n ] # EXIT NMAP
                                then   
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

        # DIRB
        elif [[ $tool = 2 ]]  # DIRB
            then
                echo "You have selected to use DIRB"
                echo "  "
                while [ $dirbon = 1 ] # RUN DIRB UNTIL QUIT
                    do
                        echo "Do you have a specific wordfile to use?"
                        echo "  "
                        read -p "YOUR SELECTION [y/n]:  " wordfileyesno
                            if [[ $wordfileyesno = y ]] # SPECIFIC WORDFILE ENTRY AND RUN
                                then
                                    read -P "Please specfiy absolute location and file:  "  wordfile
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
                            elif [[ $wordfileyesno = n ]] # DEFAULT DIRB
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
                            else
                                echo "... not an option"
                                echo "exiting DIRB ..."
                                dirbon=0
                            fi
                        echo "  "
                        echo "  "
                        read -p "Would you like to run a massive DIRB scan? [y/n]:  " massivedirb
                            if [[ $massivedirb = y ]] # RUN MASSIVE DIRB SCAN
                                then
                                    dirb http://$ip files/dirb/*.txt -w -o output_files/dirb_massive_$ip\_$DATE.txt
                                    dirbon=0
                            elif [[ $massivedirb = n ]] # EXIT DIRB
                                then   
                                    dirbon=0
                            else   
                                echo "... not an option"
                                echo "exiting DIRB ..."
                                dirbon=0
                            fi
                    echo "  "
                    done
        elif [[ $tool = 3 ]] # GOBUSTER
            then
                echo "Coming Soon..."
        fi
    done