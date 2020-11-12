#!/bin/sh

config=$1

echo config:$config

[ -f "$config" ] || {
	logger "usync_apply: invalid paramters"
	exit 1
}

utpl -m uci -m fs -E capab=/etc/usync/capabilities.json -E cfg=$1 -i /usr/share/usync/usync.tpl > /tmp/usync.uci

[ $? -eq 0 ] || {
	logger "usync_apply: applying $1 failed"
	exit 1
}

active=$(readlink /etc/usync/usync.active)
[ -n "$active" -a -f "$active" ] && {
	rm -f /etc/usync/usync.old
	ln -s $active /etc/usync/usync.old
}

rm -f /etc/usync/usync.active
ln -s $config /etc/usync/usync.active

rm -rf /tmp/config-shadow
cp -r /etc/config-shadow /tmp
cp /rom/etc/config/dhcp /tmp/config-shadow
cp /rom/etc/config/dropbear /tmp/config-shadow
cp /rom/etc/config/firewall /tmp/config-shadow
cat /tmp/usync.uci | uci -c /tmp/config-shadow batch 2> /dev/null
uci -c /tmp/config-shadow commit

cp /tmp/config-shadow/* /etc/config/

reload_config

rm -rf /tmp/config-shadow

return 0
