import logging
import meshtastic
import meshtastic.serial_interface
import meshtastic.tcp_interface
from haversine import haversine
import time
from meshtastic import portnums_pb2, mesh_pb2
from meshtastic.__init__ import LOCAL_ADDR, BROADCAST_NUM, BROADCAST_ADDR
import os

from pubsub import pub

local_interface = None
remote_interface = None
bridge_logger = logging.getLogger(name="meshtastic.bridge")

BRIDGE_LOG = os.environ['BRIDGE_LOG'] if 'BRIDGE_LOG' in os.environ else 'INFO'
NODE_LOG = os.environ['NODE_LOG'] if 'NODE_LOG' in os.environ else 'INFO'

if BRIDGE_LOG == 'DEBUG':
    bridge_logger.setLevel(logging.DEBUG)
elif BRIDGE_LOG == 'INFO':
    bridge_logger.setLevel(logging.INFO)

if NODE_LOG == 'DEBUG':
    logging.basicConfig(level=logging.DEBUG)
elif NODE_LOG == 'INFO':
    logging.basicConfig(level=logging.INFO)

local_node_addr = os.environ['LOCAL_NODE_ADDR'] if 'LOCAL_NODE_ADDR' in os.environ else None
remote_node_addr = os.environ['REMOTE_NODE_ADDR']

if local_node_addr and '/' in local_node_addr:
    bridge_logger.debug(f"Connecting to local node via serial port: {local_node_addr} ...")
    local_interface = meshtastic.serial_interface.SerialInterface(devPath=local_node_addr)
elif local_node_addr:
    bridge_logger.debug(f"Connecting to local node via TCP: {local_node_addr} ...")
    local_interface = meshtastic.tcp_interface.TCPInterface(hostname=local_node_addr)
else:
    bridge_logger.debug(f"Connecting to local node via serial port ...")
    local_interface = meshtastic.serial_interface.SerialInterface()

bridge_logger.info(f"Connected to local node")

bridge_logger.debug(f"Connecting to remote node via TCP: {remote_node_addr} ...")
remote_interface = meshtastic.tcp_interface.TCPInterface(hostname=remote_node_addr)
bridge_logger.info(f"Connected to remote node")
ourNode = local_interface.getNode('^local')

SUPPORTED_MESSAGES = [
 'POSITION_APP',
 'TEXT_MESSAGE_APP'
]

SUPPORTED_BRIDGE_DISTANCE_KM = int(os.environ['BRIDGE_DISTANCE_KM']) if 'BRIDGE_DISTANCE_KM' in os.environ else 0
CHANNEL_INDEX = 0
NODE_PROXY = {BROADCAST_ADDR: BROADCAST_ADDR}

def onReceive(packet, interface): # called when a packet arrives

    bridge_logger.debug(f"Packet received: {packet}")

    if packet['decoded']['portnum'] not in SUPPORTED_MESSAGES:
        bridge_logger.debug(f"Dropping {packet['decoded']['portnum']}")
        return

    message_source_position = None
    current_local_position = None

    if 'position' in packet['decoded']:

        if 'latitude' in packet['decoded']['position'] and 'longitude' in packet['decoded']['position']:
            message_source_position = (packet['decoded']['position']['latitude'], packet['decoded']['position']['longitude'])

            nodeInfo = local_interface.getMyNodeInfo()
            current_local_position = (nodeInfo['position']['latitude'], nodeInfo['position']['longitude'])

        if message_source_position and current_local_position:

            distance_km = haversine(message_source_position, current_local_position)

            # message originates from too far a distance
            if SUPPORTED_BRIDGE_DISTANCE_KM > 0 and distance_km > SUPPORTED_BRIDGE_DISTANCE_KM:
                bridge_logger.debug(f"Packet from too far: {distance_km} > {SUPPORTED_BRIDGE_DISTANCE_KM}")
                return

    if 'to' in packet:
        # Broadcast messages or specific 
        if packet['to'] in NODE_PROXY:
            destinationId = NODE_PROXY[packet['to']]
        else:
            destinationId = packet['to']

        channelIndex = CHANNEL_INDEX

        meshPacket = mesh_pb2.MeshPacket()
        meshPacket.channel = channelIndex
        meshPacket.decoded.payload = packet['decoded']['payload']
        meshPacket.decoded.portnum = packet['decoded']['portnum']
        meshPacket.decoded.want_response = False
        meshPacket.id = remote_interface._generatePacketId()

        if destinationId == BROADCAST_ADDR or destinationId in remote_interface.nodes:
            bridge_logger.debug(f"Sending packet {meshPacket.id} to TCP server")
            remote_interface._sendPacket(meshPacket=meshPacket, destinationId=destinationId)

def onConnection(interface, topic=pub.AUTO_TOPIC): # called when we (re)connect to the radio
    print("Connected.")

pub.subscribe(onReceive, "meshtastic.receive")
pub.subscribe(onConnection, "meshtastic.connection.established")

while True:
    time.sleep(1000)

local_interface.close()
remote_interface.close()
