# uCentral Client

uCentral Client application for OpenWiFi access points, communicating with the
[uCentral Gateway](https://github.com/Telecominfraproject/wlan-cloud-ucentralgw).
 
This software is a part of the OpenWiFi
[AP NOS](https://github.com/Telecominfraproject/wlan-ap).

## Developer Notes

The uCentral connection uses the WebSocket protocol, and messages are
transferred in JSON-RPC format. Full details of this protocol can be found in a
separate document
[here](https://github.com/Telecominfraproject/wlan-cloud-ucentralgw/blob/master/PROTOCOL.md).

- Incoming JSON-RPC messages are handled in `proto.c:proto_handle()`.
- Complex actions are executed via task queues (`libubox/runqueue.h`).
- Many actions will fork external programs, notably ucode scripts installed by
  the [ucentral-schema](https://github.com/Telecominfraproject/wlan-ucentral-schema)
  package (see [ucentral-schema/command/](https://github.com/Telecominfraproject/wlan-ucentral-schema/tree/main/command)).

This application registers several ubus methods under the `ucentral` object, as
defined in `ubus.c:ubus_object`.
