#!/bin/bash 

export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin 
reports_raw = /opt/ptx/nmap/reports_raw/ 
date_of_d = $(date "+%Y-%m-%d") 
list_of_networks = /opt/ptx/nmap/networks_list.txt 

### We check if no nmap scan are still in progress 
ps -ef | grep -v grep | grep nmap > /dev/null 2>&1 
if [ $? == 0 ] 
then 
    echo "Nmap is still running" 
    exit 
fi 

### Running Nmap 
nmap -iL $list_of_networks -P0 -T4 -oG ${reports_raw}/scan-${date_of_d}.txt 
