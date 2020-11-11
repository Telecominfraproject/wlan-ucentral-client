#!/bin/sh

utpl -m ubus -i /usr/share/usync/state.tpl -E cfg=/etc/usync/usync.active > /tmp/usync.state

