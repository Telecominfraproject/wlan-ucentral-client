#!/bin/sh

config=$1
uuid=$2

echo config:$config uuid:$uuid

[ -f "$config" -a -n "$uuid" ] || {
	echo "invalid paramters"
	exit 1
}

echo jsonschema $1 /usr/share/usync/usync.schema.json
jsonschema $1 /usr/share/usync/usync.schema.json > /dev/null

[ $? -eq 0 ] || {
	echo "schema failed"
	exit 1
}

cp $config /etc/usync/usync.cfg.$uuid

return 0
