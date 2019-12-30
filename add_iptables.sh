#!/bin/bash


ip_list=`cat /etc/hosts|grep -vE "127|localhost"|cut -d " " -f 1`


for ip in $ip_list;do 
        firewall-cmd  --permanent --add-rich="rule family='ipv4' source address='$ip' accept"
done

#accept 192.168.10.0/24
firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='192.168.10.0/24' accept"


firewall-cmd --reload

