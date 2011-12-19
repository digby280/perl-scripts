#!/bin/bash
# Extract IPs from the new config files AND put them into tcpdump string

grep -e '<channel>' $1 | sed -e 's/[ ]*<channel>[ ]*[0-9]* [a-z:]*[0-9]* \([0-9.]*\) \([0-9]*\)[ 0-9<>\/a-z]*/(dst host \1 and port \2) or /' | sed -e :a -e '$!N;s/\n//;ta' | sed -e 's/[a-z ]*$//'
