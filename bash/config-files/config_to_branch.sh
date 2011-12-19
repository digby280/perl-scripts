#!/bin/bash

~/PDK/Software/Bin/convert_config.py $1
echo -n "Converting $1..."
cp $1 $1.tmp
cat $1.tmp | ~/scripts/config_to_branch.py  > $1
rm $1.tmp
echo "done!"