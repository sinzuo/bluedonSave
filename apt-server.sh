#!/bin/bash
interf=`ip addr|grep 192.168.0.1|awk '{print $7}'`
eth=$interf:2
if [ ! -f "/etc/sysconfig/network-scripts/ifcfg-$eth" ];then
cat>/etc/sysconfig/network-scripts/ifcfg-$eth<<EOF
HWADDR=00:13:32:0E:5C:1A
TYPE=Ethernet
BOOTPROTO=static
DEFROUTE=yes
PEERDNS=yes
PEERROUTES=yes
IPV4_FAILURE_FATAL=no
#IPV6INIT=yes
#IPV6_AUTOCONF=yes
#IPV6_DEFROUTE=yes
#IPV6_PEERDNS=yes
#IPV6_PEERROUTES=yes
#IPV6_FAILURE_FATAL=no
NAME=enp11s0:0
IPADDR=172.16.110.125
NETMASK=255.255.255.126
GATEWAY=172.16.110.126
DNS1=114.114.114.114
DNS2=8.8.8.8
EOF
fi

ip=$1
mask=$2
gw=$3
kafkaip=$4
file=/etc/hosts
if [ ${#} -eq 4 ];then
        sed -i "15c IPADDR=$ip" /etc/sysconfig/network-scripts/ifcfg-$eth
        sed -i "16c NETMASK=$mask" /etc/sysconfig/network-scripts/ifcfg-$eth
        sed -i "17c GATEWAY=$gw" /etc/sysconfig/network-scripts/ifcfg-$eth
        if_exist=`cat /etc/hosts|grep -n kafka|wc -l`
        if [ $if_exist -ne 0 ];then
                num=`cat /etc/hosts|grep -n kafka|awk -F ":" '{print $1}'|head -1`
                sed -i "${num}c $kafkaip  kafka" $file
        else
                echo $kafkaip  kafka >> $file
        fi
#        nohup service network restart &
fi
echo ok
exit 0

