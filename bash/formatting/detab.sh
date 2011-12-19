#!/bin/bash

for i in $*; do 
    echo -n "$i..."
    if [ -e $i ]; then
       cp $i $i.tmp
       expand -t 4 $i.tmp > $i
       rm $i.tmp
       echo "done"
    else
       echo "failed - file not found"
    fi
done
