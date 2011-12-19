#!/bin/bash

if [ -e $1 ]; then
	echo -n "converting $1..."
	grep -q '/etc/celoxica/config.dtd' $1
	if [ "$?" -eq 0 ]; then
		sed 's:/etc/celoxica:${CELOXICA_DTD_PATH\:=/usr/share/celoxica/etc}:g' $1 > $1.tmp
		mv $1.tmp $1
		echo "done!"
	else
		echo "skipped!"
	fi
fi
