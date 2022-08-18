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

local_node_addr = os.environ['LOCAL_NODE_ADDR'] if 'LOCAL_NODE_ADDR' in os.environ else None
remote_node_addr = os.environ['REMOTE_NODE_ADDR']

if local_node_addr and '/' in local_node_addr:
    local_interface = meshtastic.serial_interface.SerialInterface(devPath=local_node_addr)
elif local_node_addr and '.' in local_node_addr:
    local_interface = meshtastic.tcp_interface.TCPInterface(hostname=local_node_addr)
else:
    local_interface = meshtastic.serial_interface.SerialInterface()

remote_interface = meshtastic.tcp_interface.TCPInterface(hostname=remote_node_addr)

ourNode = local_interface.getNode('^local')

SUPPORTED_MESSAGES = [
 'POSITION_APP',
 'TEXT_MESSAGE_APP'
]

SUPPORTED_BRIDGE_DISTANCE_KM = 5
CHANNEL_INDEX = 0
NODE_PROXY = {BROADCAST_ADDR: BROADCAST_ADDR}

def onReceive(packet, interface): # called when a packet arrives

    if packet['decoded']['portnum'] not in SUPPORTED_MESSAGES:
        print(f"Dropping {packet['decoded']['portnum']}")
        return

    message_source_position = None
    current_local_position = None

    if 'position' in packet['decoded']:

        if 'latitude' in packet['decoded']['position'] and 'longitude' in packet['decoded']['position']:
            message_source_position = (packet['decoded']['position']['latitude'], packet['decoded']['position']['longitude'])

            nodeInfo = local_interface.getMyNodeInfo()
            current_local_position = (nodeInfo['position']['latitude'], nodeInfo['position']['longitude'])

        if message_source_position and current_local_position:
            # message originates from too far a distance
            if SUPPORTED_BRIDGE_DISTANCE_KM > 0 and haversine(message_source_position, current_local_position) > SUPPORTED_BRIDGE_DISTANCE_KM:
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
            print(f"Sending {meshPacket} to TCP server")
            remote_interface._sendPacket(meshPacket=meshPacket, destinationId=destinationId)

def onConnection(interface, topic=pub.AUTO_TOPIC): # called when we (re)connect to the radio
    print("Connected.")

pub.subscribe(onReceive, "meshtastic.receive")
pub.subscribe(onConnection, "meshtastic.connection.established")

while True:
    time.sleep(1000)

local_interface.close()
remote_interface.close()
