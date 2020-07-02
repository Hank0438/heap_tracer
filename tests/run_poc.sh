#!/bin/sh

if [ $# -lt 1 ];
then
    echo "Usage: $0 <libc-version> <path/to/poc>"
    exit 1
fi

echo $$ 
cmd=$(LD_PRELOAD="./$1/libc.so.6" "./$1/ld-linux-x86-64.so.2" "$2" 2>&1)
exec $cmd
#exec "/bin/sh"
#cat /var/run/aaa.pid