#!/bin/bash

if [ $# -ne 1 ]; then
	echo "not enough args"
	exit 1
fi

lower=`echo $1 | tr '[:upper:]' '[:lower:]'`
upper=`echo $1 | tr '[:lower:]' '[:upper:]'`
cp -vv -t . ~/PDK/Examples/GMAC/config_$lower.cfg
cp -vv -t . ~/PDK/Examples/AMDC/common/$upper/streamer-test.cfg
if [ -e streamer-test.cfg ]; then
	~/PDK/Software/Bin/unconvert_config.py -rx streamer-test.cfg
fi
