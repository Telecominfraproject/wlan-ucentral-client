#!/bin/sh

config=$1

echo config:$config

[ -f "$config" ] || {
	echo "invalid paramters"
	exit 1
}

utpl -m fs -E capab=/etc/usync/capabilities.json -E cfg=$1 -i /usr/share/usync/usync.tpl

[ $? -eq 0 ] || {
	echo "applying $1 failed"
	exit 1
}

active=$(readlink /etc/usync/usync.active)
[ -n "$active" -a -f "$active" ] && {
	rm -f /etc/usync/usync.old
	ln -s $active /etc/usync/usync.old
}

rm -f /etc/usync/usync.active
ln -s $config /etc/usync/usync.active

return 0
