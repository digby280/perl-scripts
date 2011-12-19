#!/bin/bash
if [ $# -eq 0 ]; then
	echo "Usage: $0 <log-file>*"
fi
for file in $@ ; do
	gawk 'BEGIN{ show=1; }; { if ( $3 == "heartbeat" || $2 == "heartbeat" ) show=0; if ( show ) print $0; if ( $1 == "-------------" ) show=1; }' $file | gawk 'BEGIN{ show=1; }; { if ( $0 != "" ) show=1; if (show) print $0; if ( $0 == "" ) show=0; }'
done
