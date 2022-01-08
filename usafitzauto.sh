#!/bin/bash

DAY=$(date +%u)
DATE=$(date +%Y%b%d-%T)
nmapon=1

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
        while [ nmapon = 1 ]
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
                            nmap -A -T4 -p- $ip
                            echo "  "
                            echo "END COMMON NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
                    elif [[ $namppreference = 2 ]] 
                        then
                            echo "BEGIN VULN NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
                            nmap -sV -vv --script vuln $ip
                            echo "  "
                            echo "END VULN NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
                    else
                        exit 1
                    fi  
                read -P "Would you like to run another NMAP scan? [y/n]:  " runanswer
                    if [ runanswer = y ]
                        then
                            nmapon = 1
                    elif [ runanswer = n ]
                        then   
                            nmapon = 0
                    else  
                        echo "... not an option"
                        echo "exiting script..." 
                        exit 1
                    fi
            done
            echo "  "
            echo "Exiting script..."
   
elif [[ $tool = 2 ]]  # DIRB
    then
        echo "You have selected to use DIRB"
        echo "  "
        while [ dirbon = 1 ]
            do
                echo "Do you have a specific wordfile to use?"
                read -p "YOUR SELECTION [y/n]:  " wordfileyesno
                    if [[ $wordfileyesno = y ]]  
                        then
                            read -P "Please specfiy absolute location and file:  "  wordfile
                            echo "  " 
                            echo "BEGIN DIRB SCAN OF $ip -- {[$DAY] - $DATE}"
                            echo "  "
                            dirb http://$ip $wordfile
                            echo " "
                            echo "END DIRB SCAN OF $ip -- {[$DAY] - $DATE}"
                    elif [[ $wordfileyesno = n ]] 
                        then
                            echo "  " 
                            echo "BEGIN DIRB SCAN OF $ip -- {[$DAY] - $DATE}"
                            echo "  " 
                            dirb http://$ip files/dirb/common.txt
                            echo " "
                            echo "END DIRB SCAN OF $ip -- {[$DAY] - $DATE}"
                    else
                        echo "... not an option"
                        echo "exiting script..."
                        exit 1
                    fi
                read -P "Would you like to run another DIRB scan? [y/n]:  " runanswer
                    if [ runanswer = y ]
                        then
                            dirbon = 1
                    elif [ runanswer = n ]
                        then   
                            dirbon = 0
                    else   
                        exit 1
                    fi
            done
            echo "  "
            echo "Exiting script..."

else
	exit 1
fi