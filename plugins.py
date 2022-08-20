from haversine import haversine
from meshtastic import mesh_pb2
from meshtastic.__init__ import BROADCAST_ADDR
import logging
import os

plugins = {}


class Plugin:
    def configure(self, devices, config):
        self.config = config
        self.devices = devices

        if "log_level" in config:
            if config["log_level"] == "debug":
                self.logger.setLevel(logging.DEBUG)
            elif config["log_level"] == "info":
                self.logger.setLevel(logging.INFO)

    def do_action(self, packet):
        pass


class DebugFilter(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.plugin.logging")

    def do_action(self, packet):
        self.logger.info(
            f"{packet['id']} | {packet['fromId']}=>{packet['toId']} | {packet['decoded']['portnum']}"
        )
        self.logger.debug(packet)
        return packet


plugins["debugger"] = DebugFilter()


class MessageFilter(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.filter.message")

    def do_action(self, packet):
        if not packet:
            self.logger.error("Missing packet")
            return packet

        filters = {
            "app": packet["decoded"]["portnum"],
            "from": packet["fromId"],
            "to": packet["toId"],
        }

        for filter_key, value in filters.items():
            if filter_key in self.config:
                filter_val = self.config[filter_key]
                if (
                    "allow" in filter_val
                    and filter_val["allow"]
                    and value not in filter_val["allow"]
                ):
                    self.logger.debug(f"Dropped because it doesn't match allow filter")
                    return None

                if (
                    "disallow" in filter_val
                    and filter_val["disallow"]
                    and value in filter_val["disallow"]
                ):
                    self.logger.debug(f"Dropped because it matches disallow filter")
                    return None

        self.logger.debug(f"Accepted")
        return packet


plugins["message_filter"] = MessageFilter()


class DistanceFilter(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.filter.distance")

    def do_action(self, packet):
        if 'device' not in self.config:
            return packet

        if "position" not in packet["decoded"]:
            return packet

        message_source_position = None
        current_local_position = None

        if (
            "latitude" in packet["decoded"]["position"]
            and "longitude" in packet["decoded"]["position"]
        ):
            message_source_position = (
                packet["decoded"]["position"]["latitude"],
                packet["decoded"]["position"]["longitude"],
            )

            nodeInfo = self.devices[self.config["device"]].getMyNodeInfo()
            current_local_position = (
                nodeInfo["position"]["latitude"],
                nodeInfo["position"]["longitude"],
            )

        if message_source_position and current_local_position:

            distance_km = haversine(message_source_position, current_local_position)

            # message originates from too far a distance
            if (
                "max_distance_km" in self.config
                and self.config["max_distance_km"] > 0
                and distance_km > self.config["max_distance_km"]
            ):
                logger.debug(
                    f"Packet from too far: {distance_km} > {SUPPORTED_BRIDGE_DISTANCE_KM}"
                )
                return None

        return packet


plugins["distance_filter"] = DistanceFilter()


class WebhookPlugin(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.plugin.webhook")

    def do_action(self, packet):
        if "active" in self.config and not self.config["active"]:
            return packet

        if "position" not in packet["decoded"]:
            return packet

        import json
        import requests

        macros = {
            "{LAT}": packet["decoded"]["position"]["latitude"],
            "{LNG}": packet["decoded"]["position"]["longitude"],
            "{MSG}": self.config["message"] if "message" in self.config else "",
            "{FID}": packet["fromId"],
            "{TID}": packet["toId"],
        }

        body = self.config["body"]

        for macro, value in macros.items():
            body = body.replace(macro, str(value))

        payload = json.loads(body)

        self.logger.debug(f"Sending http POST request to {self.config['url']}")

        # pass secrets from environment variables to request headers
        headers = self.config["headers"] if "headers" in self.config else {}
        for k, v in headers.items():
            for ek, ev in os.environ.items():
                needle = "{" + ek + "}"
                if needle in v:
                    v = v.replace(needle, ev)

            headers[k] = v

        response = requests.post(self.config["url"], headers=headers, json=payload)

        if not response.ok:
            self.logger.warning(f"Error returned: {response.status_code}")

        return packet


plugins["webhook"] = WebhookPlugin()


class SendPlugin(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.plugin.send")

    def do_action(self, packet):

        if self.config["device"] not in self.devices:
            self.logger.error(f"Missing interface for device {self.config['device']}")
            return packet

        if "to" not in packet:
            self.logger.debug("Not a message")
            return packet

        # Broadcast messages or specific
        if (
            "node_mapping" in self.config
            and packet["to"] in self.config["node_mapping"]
        ):
            destinationId = self.config["node_mapping"][packet["to"]]
        else:
            destinationId = packet["to"]

        if "to" in self.config:
            destinationId = self.config["to"]

        device_name = self.config["device"]
        device = self.devices[device_name]

        self.logger.debug(f"Sending packet to {device_name}")

        if "message" in self.config and self.config["message"]:
            device.sendText(text=self.config["message"], destinationId=destinationId)
        elif (
            "lat" in self.config
            and self.config["lat"] > 0
            and "lng" in self.config
            and self.config["lng"] > 0
        ):
            lat = self.config["lat"]
            lng = self.config["lng"]
            altitude = self.config["alt"] if "alt" in self.config else 0

            device.sendPosition(
                latitude=lat,
                longitude=lng,
                altitude=altitude,
                destinationId=destinationId,
            )
        else:
            meshPacket = mesh_pb2.MeshPacket()
            meshPacket.channel = 0
            meshPacket.decoded.payload = packet["decoded"]["payload"]
            meshPacket.decoded.portnum = packet["decoded"]["portnum"]
            meshPacket.decoded.want_response = False
            meshPacket.id = device._generatePacketId()

            self.logger.debug(
                f"Sending packet {meshPacket.id} to {self.config['device']}"
            )
            device._sendPacket(meshPacket=meshPacket, destinationId=destinationId)

        return packet


plugins["send_plugin"] = SendPlugin()
