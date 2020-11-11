#!/bin/sh

config=$1
uuid=$2

[ -f "$config" -a -n "$uuid" ] || {
	logger "usync_verify: invalid paramters"
	exit 1
}

jsonschema $1 /usr/share/usync/usync.schema.json > /tmp/usync.verify

[ $? -eq 0 ] || {
	logger "usync_verify: schema failed"
	exit 1
}

cp $config /etc/usync/usync.cfg.$uuid

return 0
