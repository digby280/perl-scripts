#!/usr/bin/python

import sys

for line in sys.stdin:
	lineArray = filter(lambda x: x != '', line.split(' '))
	if ( lineArray[0] == '<channel>' ):
		for character in line:
			if character == ' ':
				print '',
			else:
				break
		tail = lineArray[5:]
		print lineArray[0] + ' ' + lineArray[1] + ' 0 lldt ' + lineArray[2][3:] + ' ' + lineArray[3] + ':' + lineArray[4],
		for word in tail:
			print word,
	else:
		print line,
