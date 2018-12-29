#!/bin/bash

if [ $# -lt 2 ]; then
    echo "need stack and create/remove"
    exit 1
fi

case "$2" in
    create)
	for i in platform cluster application; do
	    go run main.go -d mexos -stack $1 $i $2
	done
    ;;
    remove)
	for i in application cluster platform ; do
	    go run main.go -d mexos -stack $1 $i $2
	done	
    ;;
    *)
	echo invalid operation, must be create or remove
	exit 1
    ;;
esac
exit 0

