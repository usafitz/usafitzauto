#!/bin/bash

DAY=$(date +%u)
DATE=$(date +%Y%b%d-%T)
nmapon=1
dirbon=1

read -p "Which IP Address?  " ip
echo "  "
echo "  "
echo "--ENTER YOUR SELECTION--"
echo "1 NMAP " 
echo "2 DIRB "
echo "3 GOBUSTER "
echo "       "
read -p "TOOL SELECTION: " tool

if [[ $tool = 1 ]] # NMAP
    then
        echo "You have selected to use NMAP"
        echo "  "
        while [ $nmapon = 1 ]
            do 
                echo "Which type of scan would you like?"
                echo "1 Common & Popular"
                echo "2 High Enumeration"
                echo "  "
                read -p "YOUR SELECTION:  " namppreference
                echo "  "
                    if [[ $namppreference = 1 ]] 
                        then
                            echo "BEGIN COMMON NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
                            echo "  "
                            nmap -A -T4 -p- -oN nmap_$ip\_$DATE.txt $ip
                            echo "  "
                            echo "END COMMON NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
                            echo "  "
                    elif [[ $namppreference = 2 ]] 
                        then
                            echo "BEGIN VULN NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
                            nmap -sV -vv --script vuln -oN nmap_$ip\_$DATE.txt $ip
                            echo "  "
                            echo "END VULN NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
                            echo "  "
                    else
                        exit 1
                    fi  
                read -p "Would you like to run another NMAP scan? [y/n]:  " runanswer
                    if [ $runanswer = y ]
                        then
                            nmapon=1
                    elif [ $runanswer = n ]
                        then   
                            nmapon=0
                    else  
                        echo "... not an option"
                        echo "exiting script..." 
                        exit 1
                    fi
            echo "  " 
            done
            echo "  "
            echo "Exiting script..."
   
elif [[ $tool = 2 ]]  # DIRB
    then
        echo "You have selected to use DIRB"
        echo "  "
        while [ $dirbon = 1 ]
            do
                echo "Do you have a specific wordfile to use?"
                read -p "YOUR SELECTION [y/n]:  " wordfileyesno
                    if [[ $wordfileyesno = y ]]  
                        then
                            read -P "Please specfiy absolute location and file:  "  wordfile
                            echo "  " 
                            echo "BEGIN DIRB SCAN OF $ip -- {[$DAY] - $DATE}"
                            echo "DEFAULT:  dirb http://$ip $wordfile -N 302 -w -v"
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
                            dirb http://$ip $wordfile -N 302 -w -v
                            echo " "
                            echo "END DIRB SCAN OF $ip -- {[$DAY] - $DATE}"
                            echo " "
                    elif [[ $wordfileyesno = n ]] 
                        then
                            echo "  " 
                            echo "BEGIN DIRB SCAN OF $ip -- {[$DAY] - $DATE}"
                            echo "DEFAULT:  http://$ip files/dirb/common.txt -N 302 -w -v"
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
                            dirb http://$ip files/dirb/common.txt -N 302 -w -v
                            echo " "
                            echo "END DIRB SCAN OF $ip -- {[$DAY] - $DATE}"
                            echo "  "
                    else
                        echo "... not an option"
                        echo "exiting script..."
                        exit 1
                    fi
                read -p "Would you like to run another DIRB scan? [y/n]:  " runanswer
                    if [ $runanswer = y ]
                        then
                            dirbon=1
                    elif [ $runanswer = n ]
                        then   
                            dirbon=0
                    else   
                        exit 1
                    fi
            echo "  "
            done
            echo "  "
            echo "Exiting script..."

else
	exit 1
fi