from haversine import haversine
from meshtastic import mesh_pb2
from random import randrange
import base64
import json
import logging
import os
import re
import ssl
import math

plugins = {}


class Plugin(object):
    def __init__(self) -> None:
        self.logger.setLevel(logging.INFO)

    def configure(self, devices, mqtt_servers, config):
        self.config = config
        self.devices = devices
        self.mqtt_servers = mqtt_servers

        if config and "log_level" in config:
            if config["log_level"] == "debug":
                self.logger.setLevel(logging.DEBUG)
            elif config["log_level"] == "info":
                self.logger.setLevel(logging.INFO)

    def do_action(self, packet):
        pass


class PacketFilter(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.filter.packet")

    def strip_raw(self, data):
        if type(data) is not dict:
            return data

        if "raw" in data:
            del data["raw"]

        for k, v in data.items():
            data[k] = self.strip_raw(v)

        return data

    def normalize(self, dict_obj):
        """
        Packets are either a dict, string dict or string
        """
        if type(dict_obj) is not dict:
            try:
                dict_obj = json.loads(dict_obj)
            except:
                dict_obj = {"decoded": {"text": dict_obj}}

        return self.strip_raw(dict_obj)

    def do_action(self, packet):
        self.logger.debug(f"Before normalization: {packet}")
        packet = self.normalize(packet)

        if "decoded" in packet and "payload" in packet["decoded"]:
            if type(packet["decoded"]["payload"]) is bytes:
                text = packet["decoded"]["payload"]
                packet["decoded"]["payload"] = base64.b64encode(
                    packet["decoded"]["payload"]
                ).decode("utf-8")

        self.logger.debug(f"After normalization: {packet}")

        return packet


plugins["packet_filter"] = PacketFilter()


class DebugFilter(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.plugin.logging")

    def do_action(self, packet):
        self.logger.debug(packet)
        return packet


plugins["debugger"] = DebugFilter()


class MessageFilter(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.filter.message")

    def do_action(self, packet):
        if not packet:
            self.logger.error("Missing packet")
            return packet

        text = packet["decoded"]["text"] if "text" in packet["decoded"] else None

        if text and "message" in self.config:
            if "allow" in self.config["message"]:
                matches = False
                for allow_regex in self.config["message"]["allow"]:
                    if not matches and re.search(allow_regex, text):
                        matches = True

                if not matches:
                    self.logger.debug(
                        f"Dropped because it doesn't match message allow filter"
                    )
                    return None

            if "disallow" in self.config["message"]:
                matches = False
                for disallow_regex in self.config["message"]["disallow"]:
                    if not matches and re.search(disallow_regex, text):
                        matches = True

                if matches:
                    self.logger.debug(
                        f"Dropped because it matches message disallow filter"
                    )
                    return None

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
                    self.logger.debug(
                        f"Dropped because {value} doesn't match {filter_key} allow filter"
                    )
                    return None

                if (
                    "disallow" in filter_val
                    and filter_val["disallow"]
                    and value in filter_val["disallow"]
                ):
                    self.logger.debug(
                        f"Dropped because {value} matches {filter_key} disallow filter"
                    )
                    return None

        self.logger.debug(f"Accepted")
        return packet


plugins["message_filter"] = MessageFilter()


class LocationFilter(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.filter.distance")

    def do_action(self, packet):
        message_source_position = None
        current_local_position = None

        if "device" in self.config and self.config["device"] in self.devices:
            nodeInfo = self.devices[self.config["device"]].getMyNodeInfo()
            current_local_position = (
                nodeInfo["position"]["latitude"],
                nodeInfo["position"]["longitude"],
            )

        if (
            "decoded" in packet
            and "position" in packet["decoded"]
            and "latitude" in packet["decoded"]["position"]
            and "longitude" in packet["decoded"]["position"]
        ):
            message_source_position = (
                packet["decoded"]["position"]["latitude"],
                packet["decoded"]["position"]["longitude"],
            )

        if "compare_latitude" in self.config and "compare_longitude" in self.config:
            current_local_position = (
                self.config["compare_latitude"],
                self.config["compare_longitude"],
            )

        if message_source_position and current_local_position:
            distance_km = haversine(message_source_position, current_local_position)

            comparison = (
                self.config["comparison"] if "comparison" in self.config else "within"
            )

            # message originates from too far a distance
            if "max_distance_km" in self.config and self.config["max_distance_km"] > 0:
                acceptable_distance = self.config["max_distance_km"]

                if comparison == "within" and distance_km > acceptable_distance:
                    self.logger.debug(
                        f"Packet from too far: {distance_km} > {acceptable_distance}"
                    )
                    return None
                elif comparison == "outside" and distance_km < acceptable_distance:
                    self.logger.debug(
                        f"Packet too close: {distance_km} < {acceptable_distance}"
                    )
                    return None

        if "latitude" in self.config:
            packet["decoded"]["position"]["latitude"] = self.config["latitude"]
        if "longitude" in self.config:
            packet["decoded"]["position"]["longitude"] = self.config["longitude"]

        return packet


plugins["location_filter"] = LocationFilter()


class WebhookPlugin(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.plugin.webhook")

    def do_action(self, packet):
        if "active" in self.config and not self.config["active"]:
            return packet

        if "body" not in self.config:
            self.logger.warning("Missing config: body")
            return packet

        import requests

        position = (
            packet["decoded"]["position"] if "position" in packet["decoded"] else None
        )
        text = packet["decoded"]["text"] if "text" in packet["decoded"] else None

        macros = {
            "{LAT}": position["latitude"] if position else "",
            "{LNG}": position["longitude"] if position else "",
            "{MSG}": self.config["message"] if "message" in self.config else text,
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


class MQTTPlugin(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.plugin.mqtt")

    def do_action(self, packet):
        required_options = ["name", "topic"]

        for option in required_options:
            if option not in self.config:
                self.logger.warning(f"Missing config: {option}")
                return packet

        if self.config["name"] not in self.mqtt_servers:
            self.logger.warning(f"No server established: {self.config['name']}")
            return packet

        mqtt_server = self.mqtt_servers[self.config["name"]]

        if not mqtt_server.is_connected():
            self.logger.error("Not sent, not connected")
            return

        packet_message = json.dumps(packet)

        if "message" in self.config:
            message = self.config["message"].replace("{MSG}", packet["decoded"]["text"])
        else:
            message = packet_message

        info = mqtt_server.publish(self.config["topic"], message)
        info.wait_for_publish()

        self.logger.debug("Message sent")

        return packet


plugins["mqtt_plugin"] = MQTTPlugin()


class OwntracksPlugin(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.plugin.Owntracks")

    def do_action(self, packet):

        required_options = ["tid_table", "server_name"]
        for option in required_options:
            if option not in self.config:
                self.logger.warning(f"Missing config: {option}")
                return packet
        tid_table = self.config["tid_table"]

        if not "from" in packet:
            self.logger.warning("Missing from: field")
            return packet

        if not str(packet["from"]) in self.config["tid_table"]:
            self.logger.warning(f"Sender not in tid_table: {packet}")
            return packet

        from_str = str(packet["from"])

        message = json.loads('{"_type":"location", "bs":0}')
        message["tid"] = tid_table[from_str][1]
        self.logger.debug(f"processing packet {packet}")
        #Packet direct from radio
        if (
            "decoded" in packet
            and "position" in packet["decoded"]
            and "latitude" in packet["decoded"]["position"]
            and packet["decoded"]["position"]["latitude"] != 0
        ):
            message["lat"] = packet["decoded"]["position"]["latitude"]
            message["lon"] = packet["decoded"]["position"]["longitude"]
            message["tst"] = packet["decoded"]["position"]["time"]
            message["created_at"] = packet["rxTime"]
            if "altitude" in packet["decoded"]["position"]:
                message["alt"] = packet["decoded"]["position"]["altitude"]

        #packet from mqtt
        elif (
            "type" in packet
            and packet["type"] == "position"
            and "payload" in packet
            and "latitude_i" in packet["payload"]
            and packet["payload"]["latitude_i"] != 0
        ):
            message["lat"] = packet["payload"]["latitude_i"]/10000000
            message["lon"] = packet["payload"]["longitude_i"]/10000000
            message["tst"] = packet["timestamp"]
            if ("time" in packet["payload"]):
                message["created_at"] = packet["payload"]["time"]
            else:
                message["created_at"] = packet["timestamp"]
            if "altitude" in packet["payload"]:
                message["alt"] = packet["payload"]["altitude"]
        else:
            self.logger.debug("Not a location packet")
            return packet

        if self.config["server_name"] not in self.mqtt_servers:
            self.logger.warning(f"No server established: {self.config['server_name']}")
            return packet

        mqtt_server = self.mqtt_servers[self.config["server_name"]]

        if not mqtt_server.is_connected():
            self.logger.error("Not sent, not connected")
            return

        self.logger.debug("Sending owntracks message")

        info = mqtt_server.publish("owntracks/user/" + tid_table[from_str][0], json.dumps(message))
        #info.wait_for_publish()

        self.logger.debug("Message sent")

        return packet


plugins["owntracks_plugin"] = OwntracksPlugin()


class EncryptFilter(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.filter.encrypt")

    def do_action(self, packet):
        if "key" not in self.config:
            return None

        from jwcrypto import jwk, jwe
        from jwcrypto.common import json_encode, json_decode

        with open(self.config["key"], "rb") as pemfile:
            encrypt_key = jwk.JWK.from_pem(pemfile.read())

        public_key = jwk.JWK()
        public_key.import_key(**json_decode(encrypt_key.export_public()))
        protected_header = {
            "alg": "RSA-OAEP-256",
            "enc": "A256CBC-HS512",
            "typ": "JWE",
            "kid": public_key.thumbprint(),
        }

        message = json.dumps(packet)

        jwetoken = jwe.JWE(
            message.encode("utf-8"), recipient=public_key, protected=protected_header
        )

        self.logger.debug(f"Encrypted message: {packet['id']}")
        return jwetoken.serialize()


plugins["encrypt_filter"] = EncryptFilter()


class DecryptFilter(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.filter.decrypt")

    def do_action(self, packet):
        if "key" not in self.config:
            return packet

        if type(packet) is not str:
            self.logger.warning(f"Packet is not string")
            return packet

        from jwcrypto import jwk, jwe

        with open(self.config["key"], "rb") as pemfile:
            private_key = jwk.JWK.from_pem(pemfile.read())

        jwetoken = jwe.JWE()
        jwetoken.deserialize(packet, key=private_key)
        payload = jwetoken.payload
        packet = json.loads(payload)
        self.logger.debug(f"Decrypted message: {packet['id']}")
        return packet


plugins["decrypt_filter"] = DecryptFilter()


class RadioMessagePlugin(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.plugin.send")

    def do_action(self, packet):
        if self.config["device"] not in self.devices:
            self.logger.error(f"Missing interface for device {self.config['device']}")
            return packet

        destinationId = None

        if "to" in self.config:
            destinationId = self.config["to"]
        elif "toId" in self.config:
            destinationId = self.config["toId"]
        elif "node_mapping" in self.config and "to" in packet:
            destinationId = self.config["node_mapping"][packet["to"]]
        elif "to" in packet:
            destinationId = packet["to"]
        elif "toId" in packet:
            destinationId = packet["toId"]

        if not destinationId:
            self.logger.error("Missing 'to' property in config or packet")
            return packet

        device_name = self.config["device"]

        device = self.devices[device_name]

        # Not a radio packet
        if "decoded" in packet and "text" in packet["decoded"] and "from" not in packet:
            self.logger.debug(f"Sending text to Radio {device_name}")
            device.sendText(text=packet["decoded"]["text"], destinationId=destinationId)

        elif (
            "lat" in self.config
            and self.config["lat"] > 0
            and "lng" in self.config
            and self.config["lng"] > 0
        ):
            lat = self.config["lat"]
            lng = self.config["lng"]
            altitude = self.config["alt"] if "alt" in self.config else 0

            self.logger.debug(f"Sending position to Radio {device_name}")

            device.sendPosition(
                latitude=lat,
                longitude=lng,
                altitude=altitude,
                destinationId=destinationId,
            )
        elif (
            "decoded" in packet
            and "payload" in packet["decoded"]
            and "portnum" in packet["decoded"]
        ):
            meshPacket = mesh_pb2.MeshPacket()
            meshPacket.channel = 0
            meshPacket.decoded.payload = base64.b64decode(packet["decoded"]["payload"])
            meshPacket.decoded.portnum = packet["decoded"]["portnum"]
            meshPacket.decoded.want_response = False
            meshPacket.id = device._generatePacketId()

            self.logger.debug(f"Sending packet to Radio {device_name}")

            device._sendPacket(meshPacket=meshPacket, destinationId=destinationId)

        return packet


plugins["radio_message_plugin"] = RadioMessagePlugin()

class AntennaPlugin(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.plugin.Antenna")

    def do_action(self, packet):

        required_options = ["tid_local", "tid_remote", "server_name"]
        for option in required_options:
            if option not in self.config:
                self.logger.warning(f"Missing config: {option}")
                return packet
        tid_local = self.config["tid_local"]
        tid_remote = self.config["tid_remote"]
        file_path = 'vectors.json'

        if not "from" in packet:
            self.logger.warning("Missing from: field")
            return packet

        remote_lat = 10.00
        remote_lon = 10.00
        remote_alt = 10.00
        local_lat = 10.00
        local_lon = 10.00
        local_alt = 10.00
        distance = 10.00
        bearing = 10.00
        ant_elev = 10.00

        # deserialize data from last run

        with open(file_path, "r") as f:
            deserialized_dict = json.load(f)

        remote_lat = deserialized_dict["Remote"]["Latitude"]
        remote_lon = deserialized_dict["Remote"]["Longitude"]
        remote_alt = deserialized_dict["Remote"]["Altitude"]
        local_lat = deserialized_dict["Local"]["Latitude"]
        local_lon = deserialized_dict["Local"]["Longitude"]
        local_alt = deserialized_dict["Local"]["Altitude"]
#        distance = deserialized_dict[""]
        bearing = deserialized_dict["Antenna"]["Bearing"]
        ant_elev = deserialized_dict["Antenna"]["Elevation"]

        if str(packet["from"]) in self.config["tid_remote"]:
            self.logger.debug(f"Sender remote: {packet}")
            message = json.loads('{"_type":"location", "bs":0}')
            self.logger.debug(f"processing remote packet {packet}")
            #Packet direct from radio
            if (
                "decoded" in packet
                and "position" in packet["decoded"]
                and "latitude" in packet["decoded"]["position"]
                and packet["decoded"]["position"]["latitude"] != 0
            ):
                remote_lat = packet["decoded"]["position"]["latitude"]
                remote_lon = packet["decoded"]["position"]["longitude"]
                if "altitude" in packet["decoded"]["position"]:
                    remote_alt = packet["decoded"]["position"]["altitude"]

            #packet from mqtt
            elif (
                "type" in packet
                and packet["type"] == "position"
                and "payload" in packet
                and "latitude_i" in packet["payload"]
                and packet["payload"]["latitude_i"] != 0
            ):
                remote_lat = packet["payload"]["latitude_i"]/10000000
                remote_lon = packet["payload"]["longitude_i"]/10000000
                if "altitude" in packet["payload"]:
                    remote_alt = packet["payload"]["altitude"]
        elif str(packet["from"]) in self.config["tid_local"]:
            self.logger.debug(f"Sender local: {packet}")
            message = json.loads('{"_type":"location", "bs":0}')
            self.logger.debug(f"processing local packet {packet}")
            #Packet direct from radio
            if (
                "decoded" in packet
                and "position" in packet["decoded"]
                and "latitude" in packet["decoded"]["position"]
                and packet["decoded"]["position"]["latitude"] != 0
            ):
                local_lat = packet["decoded"]["position"]["latitude"]
                local_lon = packet["decoded"]["position"]["longitude"]
                if "altitude" in packet["decoded"]["position"]:
                    local_alt = packet["decoded"]["position"]["altitude"]

            #packet from mqtt
            elif (
                "type" in packet
                and packet["type"] == "position"
                and "payload" in packet
                and "latitude_i" in packet["payload"]
                and packet["payload"]["latitude_i"] != 0
            ):
                local_lat = packet["payload"]["latitude_i"]/10000000
                local_lon = packet["payload"]["longitude_i"]/10000000
                if "altitude" in packet["payload"]:
                    local_alt = packet["payload"]["altitude"]
            else:
                self.logger.debug("Not a location packet")
                return packet

        if self.config["server_name"] not in self.mqtt_servers:
            self.logger.warning(f"No server established: {self.config['server_name']}")
            return packet

        mqtt_server = self.mqtt_servers[self.config["server_name"]]

        if not mqtt_server.is_connected():
            self.logger.error("Not connected to MQTT")
            return

        self.logger.debug("Calculating antenna aim")

        """Calculate the distance in kilometers between two locations."""
        R = 6371.000  # Earth's radius in kilometers
        phi1 = math.radians(local_lat)
        phi2 = math.radians(remote_lat)
        delta_phi = math.radians(remote_lat - local_lat)
        delta_lambda = math.radians(remote_lon - local_lon)
        a = math.sin(delta_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        distance = R * c

        """Calculate the bearing in degrees from one location to another."""
        y = math.sin(delta_lambda) * math.cos(phi2)
        x = math.cos(phi1) * math.sin(phi2) - math.sin(phi1) * math.cos(phi2) * math.cos(delta_lambda)
        bearing = math.degrees(math.atan2(y, x))

        """Calculate elevation angle: To calculate the Antenna Elevation Angle,
            subtract local_alt from remote_alt.
            Subtract this result from distance.
            Then, divide this result by the distance between the antenna and the satellite.
            Finally, take the arctangent of this quotient to get the Antenna Elevation Angle."""

        phi3 = (remote_alt / 1000) - (local_alt / 1000)
        phi4 = distance - phi3
#        phi5 = phi4 / distance
        ant_calc = math.atan2(phi4, distance)
        if (ant_calc < 0):
            ant_calc += Math.PI * 2
        ant_elev = math.degrees(ant_calc)

        vectors = {
            'Antenna': {
                'Bearing': bearing, 'Distance': distance, 'Elevation': ant_elev
                },
            'Local': {
                'Latitude': local_lat, 'Longitude': local_lon, 'Altitude': local_alt
                },
            'Remote': {
                'Latitude': remote_lat, 'Longitude': remote_lon, 'Altitude': remote_alt
                },
            'Math': {
                'phi3': phi3, 'phi4': phi4
                }
            }

        self.logger.debug("Antenna aim calculated, writing to vectors.json")

        # Open the file in binary mode
        with open(file_path, 'w') as f:
            # Serialize and write the variable to the file
            json.dump(vectors, f)
            f.close()

        self.logger.debug("Write completed, file closed")

        return


plugins["Antenna_plugin"] = AntennaPlugin()


