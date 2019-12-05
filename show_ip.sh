#!/bin/bash

/bin/cp -f  /etc/issue.net /etc/issue
echo -e "this host ip:\c" >> /etc/issue
/sbin/ip addr | grep "inet" |grep -v "inet6" | grep -v "127.0.0.1" |grep -v "virbr" | awk '{print $2}'|sed  '/192.168.0.1/d'|sed  '/192.168.1.1/d' >> /etc/issue
echo "" >> /etc/issue
