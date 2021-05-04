#!/bin/bash
f="audit_Centos_7.sh"
x=`date +%Y%m%d-%H%M`
y=`hostname`
output="${y}_${x}.log"
sh $f > $output 2>&1
echo "Auditing is finished, please see the $output file"
