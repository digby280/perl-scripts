#!/bin/bash
for i in `ipcs | gawk "/$USER/{ print \\$2; }"`; do ipcrm -m$i; done
