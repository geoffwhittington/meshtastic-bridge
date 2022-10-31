import json
import logging
from re import I
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
import paho.mqtt.client as mqtt

logging.basicConfig()

logger = logging.getLogger(name="meshtastic.bridge")
logger.setLevel(logging.DEBUG)


class CustomTCPInterface(meshtastic.tcp_interface.TCPInterface):
    def __init__(self, hostname, device_name):
        self.device_name = device_name
        self.hostname = hostname
        super(CustomTCPInterface, self).__init__(hostname)


def onReceive(packet, interface):  # called when a packet arrives
    nodeInfo = interface.getMyNodeInfo()

    for pipeline, pipeline_plugins in bridge_config["pipelines"].items():
        logger.debug(f"Pipeline {pipeline} initiated")

        p = plugins["packet_filter"]
        pipeline_packet = p.do_action(packet)

        for plugin in pipeline_plugins:
            if not pipeline_packet:
                continue

            for plugin_key, plugin_config in plugin.items():

                logger.debug(f"Processing plugin: {pipeline}/{plugin_key}")
                if not pipeline_packet:
                    logger.debug("Skipping since the packet is null")
                    continue

                if plugin_key not in plugins:
                    logger.error(f"No such plugin: {plugin_key}. Skipping")
                    continue

                p = plugins[plugin_key]
                p.configure(devices, mqtt_servers, plugin_config)

                pipeline_packet = p.do_action(pipeline_packet)

        logger.debug(f"Pipeline {pipeline} completed")


def onConnection(
    interface, topic=pub.AUTO_TOPIC
):  # called when we (re)connect to the radio
    nodeInfo = interface.getMyNodeInfo()
    logger.info(
        f"Connected to node: userId={nodeInfo['user']['id']} hwModel={nodeInfo['user']['hwModel']}"
    )


def onLost(interface):
    logger.debug(f"Connecting to {interface.hostname} ...")
    devices[interface.device_name] = CustomTCPInterface(
        hostname=interface.hostname, device_name=interface.device_name
    )
    logger.debug(f"Connected to {interface.hostname}")


pub.subscribe(onReceive, "meshtastic.receive")
pub.subscribe(onConnection, "meshtastic.connection.established")
pub.subscribe(onLost, "meshtastic.connection.lost")

with open("config.yaml") as f:
    bridge_config = yaml.load(f, Loader=SafeLoader)

devices = {}
mqtt_servers = {}

for device in bridge_config["devices"]:
    if "active" in device and not device["active"]:
        continue

    if "serial" in device:
        devices[device["name"]] = meshtastic.serial_interface.SerialInterface(
            devPath=device["serial"]
        )
    elif "tcp" in device:
        logger.debug(f"Connecting to {device['tcp']} ...")
        devices[device["name"]] = CustomTCPInterface(
            hostname=device["tcp"], device_name=device["name"]
        )
        logger.debug(f"Connected to {device['tcp']}")
    else:
        devices[device["name"]] = meshtastic.serial_interface.SerialInterface()

if "mqtt_servers" in bridge_config:
    for config in bridge_config["mqtt_servers"]:
        required_options = [
            "name",
            "server",
            "port",
        ]

        for option in required_options:
            if option not in config:
                logger.warning("Missing config: {option}")

        client_id = config["client_id"] if "client_id" in config else None
        username = config["username"] if "username" in config else None
        password = config["password"] if "password" in config else None

        if client_id:
            mqttc = mqtt.Client(client_id)
        else:
            mqttc = mqtt.Client()

        if username and password:
            mqttc.username_pw_set(username, password)

        mqtt_servers[config["name"]] = mqttc

        def on_connect(mqttc, obj, flags, rc):
            logger.debug(f"Connected to MQTT {config['name']}")

        def on_message(mqttc, obj, msg):
            orig_packet = msg.payload.decode()

            logger.debug(f"MQTT {config['name']}: on_message")

            if "pipelines" not in config:
                logger.warning(f"MQTT {config['name']}: no pipeline")
                return

            for pipeline, pipeline_plugins in config["pipelines"].items():

                packet = orig_packet

                logger.debug(f"MQTT {config['name']} pipeline {pipeline} started")
                if not packet:
                    continue

                for plugin in pipeline_plugins:
                    if not packet:
                        continue

                    for plugin_key, plugin_config in plugin.items():
                        if plugin_key not in plugins:
                            logger.error(f"No such plugin: {plugin_key}. Skipping")
                            continue

                        p = plugins[plugin_key]
                        p.configure(devices, mqtt_servers, plugin_config)

                        try:
                            packet = p.do_action(packet)
                        except Exception as e:
                            logger.error(f"Hit an error: {e}", exc_info=True)
                logger.debug(f"MQTT {config['name']} pipeline {pipeline} finished")

        def on_publish(mqttc, obj, mid):
            logger.debug(f"MQTT {config['name']}: on_publish: {mid}")

        def on_subscribe(mqttc, obj, mid, granted_qos):
            logger.debug(f"MQTT {config['name']}: on_subscribe: {mid}")

        mqttc.on_message = on_message
        mqttc.on_connect = on_connect
        mqttc.on_publish = on_publish
        mqttc.on_subscribe = on_subscribe

        import ssl

        if "insecure" in config and config["insecure"]:
            mqttc.tls_set(cert_reqs=ssl.CERT_NONE)
            mqttc.tls_insecure_set(True)

        mqttc.connect(config["server"], config["port"], 60)

        if "topic" in config:
            mqttc.subscribe(config["topic"], 0)

        mqttc.loop_start()

while True:
    time.sleep(1000)

if devices:
    for device, instance in devices.items():
        instance.close()

if mqtt_servers:
    for server, instance in mqtt_servers.items():
        instance.disconnect()
