# Meshtastic Bridge

Connect two distinct radio [Meshtastic](https://meshtastic.org) networks using TCP.

WARNING: Traffic is sent insecure using TCP. Use a VPN to secure traffic between the nodes

## Requirements

- Python3
- Two Meshtastic devices:   
   - Local `LOCAL_NODE_ADDR` The IP address or Serial devPath (micro USB cable needed for serial access) of a local Meshtastic device
   - Remote `REMOTE_NODE_ADDR` The IP address of a remote Meshtastic device

Refer to <https://meshtastic.org/docs/settings/config/wifi#wifi-client> to configure a Meshtastic device to use wifi and expose a TCP address

## Setup

Run the following steps to download and install the software locally

```
$ git clone https://github.com/geoffwhittington/meshtastic-bridge.git
$ python3 -m venv meshtastic-bridge
$ cd meshtastic-bridge
$ source bin/activate
$ pip install -r requirements.txt
```

## Turn on the Bridge

In the `meshtastic-bridge` directory run the following - replacing `BRIDGE_DISTANCE_KM`, `LOCAL_NODE_ADDR` and `REMOTE_NODE_ADDR` with the proper values:

```
BRIDGE_DISTANCE_KM=0 LOCAL_NODE_ADDR=/dev/ttyUSB0 REMOTE_NODE_ADDR=182.168.86.123 python main.py
```

## Bridge Options

* `BRIDGE_DISTANCE_KM` Do not bridge messages from nodes that more than BRIDGE_DISTANCE_KM kilometers from the local Meshtastic device. Default `0` (no limit)
