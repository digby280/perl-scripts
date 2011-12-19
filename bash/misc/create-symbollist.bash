#!/bin/bash

symbolsfile=$2
refdata=$1

for sym in `cat $symbolsfile`; do sed 's/,/ /g' $refdata | egrep " $sym$"; done | gawk '{ i=lshift($1,11); print xor(i,$2); }' | sort -n
