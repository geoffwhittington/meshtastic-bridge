import logging
import meshtastic
import meshtastic.serial_interface
import meshtastic.tcp_interface
from haversine import haversine
import time
from meshtastic import portnums_pb2, mesh_pb2
from meshtastic.__init__ import LOCAL_ADDR, BROADCAST_NUM, BROADCAST_ADDR
import os
from plugins import plugins
from pubsub import pub
import yaml
from yaml.loader import SafeLoader

logger = logging.getLogger(name="meshtastic.bridge")
logger.setLevel(logging.DEBUG)

with open("config.yaml") as f:
    bridge_config = yaml.load(f, Loader=SafeLoader)

devices = {}

for device in bridge_config["devices"]:
    if "serial" in device:
        devices[device["name"]] = meshtastic.serial_interface.SerialInterface(
            devPath=device["serial"]
        )
    elif "tcp" in device:
        devices[device["name"]] = meshtastic.tcp_interface.TCPInterface(
            hostname=device["tcp"]
        )
    else:
        devices[device["name"]] = meshtastic.serial_interface.SerialInterface()


def onReceive(packet, interface):  # called when a packet arrives
    for pipeline in bridge_config["pipelines"]:

        pipeline_packet = packet

        for key, config in pipeline.items():

            if not pipeline_packet:
                continue

            if key not in plugins:
                logger.error(f"No such plugin: {key}. Skipping")
                continue

            p = plugins[key]
            p.configure(devices, config)

            pipeline_packet = p.do_action(pipeline_packet)


def onConnection(
    interface, topic=pub.AUTO_TOPIC
):  # called when we (re)connect to the radio
    nodeInfo = interface.getMyNodeInfo()

    logger.info(
        f"Connected to node: userId={nodeInfo['user']['id']} hwModel={nodeInfo['user']['hwModel']}"
    )


pub.subscribe(onReceive, "meshtastic.receive")
pub.subscribe(onConnection, "meshtastic.connection.established")

while True:
    time.sleep(1000)

for device, instance in devices.items():
    instance.close()
