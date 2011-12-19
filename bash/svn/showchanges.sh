#!/bin/bash

svn st | gawk '{ if ( $1 != "?" ) { if ( $2 != "+" ) { print $2 } else print $3 } }'
#svn diff | gawk '{ if ( $1 == "+++" ) print $2; }'
