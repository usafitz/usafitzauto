#!/bin/bash

DAY=$(date +%u)
DATE=$(date +%Y%b%d-%T)
read -p "Which IP Address?  " ip

echo "--ENTER YOUR SELECTION--"
echo "1 NMAP " 
echo "2 DIRB "
echo "3 GOBUSTER "
echo "       "
read -p "YOUR SELECTION: " answer

if [[ $answer = 1 ]] then
# NMAP
    echo "You have selected to use NMAP"
    echo "Which type of scan would you like?"
    echo "1 Common & Popular"
    echo "2 High Enumeration"
    read -p "YOUR SELECTION:  " namppreference
    echo "  "
        if [[ $nmappreference = 1]] then
            echo "BEGIN COMMON NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
            nmap -A -T4 -p- $ip
            echo " "
            echo "END COMMON NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
        elif [[ $nmappreference = 2]] then
            echo "BEGIN VULN NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
            nmap -sV -vv --script vuln $ip
            echo "  "
            echo "END VULN NMAP SCAN OF $ip -- {[$DAY] - $DATE}"
        else   
            exit 1
        fi

elif [[ $answer = 2 ]] ; then
# DIRB
    echo "You have selected to use DIRB"
    echo "Do you have a wordfile location?"
    read -p "YOUR SELECTION [y/n]:  " wordfileyesno
        if [[ $wordfileyesno = y]] ; then
            read -P "Please specfiy absolute location:  "  wordfilelocation
            echo "  " 
            echo "BEGIN DIRB SCAN OF $ip -- {[$DAY] - $DATE}"
            dirb http://$ip $wordfilelocation/common.txt
            echo " "
            echo "END DIRB SCAN OF $ip -- {[$DAY] - $DATE}"
        if [[ $wordfileyesno = n]] ; then
            echo "  " 
            echo "BEGIN DIRB SCAN OF $ip -- {[$DAY] - $DATE}"
            dirb http://$ip /usr/share/wordlists/dirb/common.txt
            echo " "
            echo "END DIRB SCAN OF $ip -- {[$DAY] - $DATE}"
        else
            exit 1
        fi


else



	exit 1

fi
