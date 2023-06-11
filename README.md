# Meshtastic Bridge

Connect [Meshtastic](https://meshtastic.org) radio networks using MQTT and HTTP.

WARNING: Work in progress

## Requirements

- Command-line install
  - Python 3.8
  - git
  - Outbound HTTPS (TCP/443) or SSH (TCP/22) access to github.com
- Docker-based install
  - Docker
- Meshtastic radio device:
  - The _IP address_ or Serial _devPath_ (micro USB cable needed for serial access) of a Meshtastic device
- MQTT server:
  - The _domain name_ of the server
  - The _port_ (e.g. 1883)

Refer to <https://meshtastic.org/docs/settings/config/wifi#wifi-client> for details on how to configure a Meshtastic device to use wifi and expose a TCP address.

## Command-line installation

Download the code and install it onto a system:

```
$ git clone https://github.com/geoffwhittington/meshtastic-bridge.git
```

Create a Python virtual environment

```
$ python3 -m venv meshtastic-bridge
```

Install the bridge dependencies

```
$ cd meshtastic-bridge
$ source bin/activate
$ pip install -r requirements.txt
```

## Docker installation

There is nothing to install with Docker, the bridge is downloaded at the time it is run

## Configuration

The bridge is configured using a YAML file `config.yaml`. It is composed of three sections, `devices`, `mqtt_servers` and `pipelines`.

An example `config.yaml` is provided below:

```
devices:
   - name: remote
     tcp: 192.168.86.39
     active: true
mqtt_servers:
   - name: external
     server: broker.hivemq.com
     port: 1883
     topic: meshtastic/radio-network1
     pipelines:
       mqtt-to-radio:
         - decrypt_filter:
            key: '/home/user/keys/key.pem'
         - radio_message_plugin:
            device: remote
pipelines:
 radio-to-mqtt:
   - encrypt_filter:
       key: '/home/user/keys/cert.pem'
   - mqtt_plugin:
       name: external
       topic: mesh/tastic
```

`devices` is a list of radios the bridge listens for packets or to where it can send packets.

- **name** Reference given to a radio that is used elsewhere in the `pipelines` configuration. For example, `my_radio`
- **tcp** The IP address of the radio. For example, `192.168.0.1` (Optional)
- **serial** The name of the serial device attached to the radio. For example, `/dev/ttyUSB0` (Optional)
- **active** Indicator whether this configuration is active. Values: `true` or `false`. Default = `true`.

NOTE: If `tcp` or `serial` are not given the bridge will attempt to detect a radio attached to the serial port. Additional configuration may be needed to use the serial port with the Docker option.

`mqtt_servers` is a list of MQTT servers the bridge listens for shared network traffic.

- **name** Reference given to the MQTT server. For example, `my_mqtt_server`
- **server** The IP address or hostname of a MQTT server. For example, `server.mqttserver.com`
- **port** The port the MQTT server listens on
- **topic** The topic name associated with the network traffic. For example, `mesh/network`
- **insecure** Use a secure connection but do not validate the server certificate
- **pipelines** A set of plugins (filters/actions) that run when a new message emerges for _topic_. Each pipeline is given a name; such as `mqtt-to-radio` (as in the example above)

`pipelines` is a list of ordered plugins (filters/actions) that run when a packet is detected by any connected radio. Each set is given a name; such as `radio-to-mqtt` (as in the example above). Pipelines can run in any order, however plugins run in the order they are defined.

## Plugins

The following plugins can be used in the `pipelines` section of `config.yaml`:

| Plugin                 | Description                                                          |
| ---------------------- | -------------------------------------------------------------------- |
| `debugger`             | Log the packet to the system console                                 |
| `message_filter`       | Filters out packets from the bridge that match a specific criteria   |
| `location_filter`      | Filters out packets that originate too far from a specified `device` |
| `webhook`              | Send HTTP requests with custom payloads using packet information     |
| `mqtt_plugin`          | Send packets to a MQTT server                                        |
| `encrypt_filter`       | Encrypt a packet for a desired MQTT recipient                        |
| `decrypt_filter`       | Decrypt a packet originating from MQTT                               |
| `radio_message_plugin` | Send a packet to a specified `device`                                |
| `nostr_plugin`         | Send a NoStr event to a relay                                        |
| `owntracks_plugin`     | Send location data to MQTT server for Owntracks                      |

### debugger - Output the contents of a packet

- **log_level** `debug` or `info`. Default `info`

For example:

```
debugger:
  log_level: debug
```

Useful for troubleshooting.

### message_filter - Allow or block packets based on criteria

- **log_level** `debug` or `info`. Default `info`
- **app** Name of meshtastic application to allow or disallow
- **from** The packet `fromId` values to allow or disallow
- **to** The packet `toId` values to allow or disallow
- **message** The packet `message` values to allow or disallow. Supports Regex.

For example:

```
message_filter:
  from:
     allow:
        - !bd5ba0ec
        - !f85bc0bc
     disallow:
        - !c15ba2ec
  message:
     disallow:
        - Good night
```

### location_filter - Filter packets by location from current node (default) or specific location

- **log_level** `debug` or `info`. Default `info`
- **max_distance_km** Filter packets more than a certain distance
- **comparison** `within` or `outside`. Default `within`
- **compare_latitude** latitude to compare against
- **compare_longitude** longitude to compare against
- **latitude** Set the latitude
- **longitude** Set the longitude

For example

```
location_filter:
  max_distance_km: 1000
```

### webhook - Send a HTTP request

- **log_level** `debug` or `info`. Default `info`
- **active** Plugin is active. Values: `true` or `false`. Default = `true`.
- **body** The JSON payload to send
- **url** The target URL
- **headers** HTTP headers to include in the request. Secrets can be passed using ENV variables
- **message** Override the packet message

Placeholders can be used with the **body** value:

- `{LAT}` - Latitude associated with the POSITION packet. Empty if no value available.
- `{LNG}` - Latitude associated with the POSITION packet. Empty if no value available.
- `{MSG}` - Packet text or `message` from the configuration (above)
- `{FID}` - The `fromId` associated with the packet.
- `{TID}` - The `toId` associated with the packet.

For example:

```
webhook:
  active: true
  body: '{"lat": "{LAT}", "lng": "{LNG}", "text_message": "{MSG}"}'
  url: 'https://localhost:8000/message'
  headers:
     Authorization: Token {AUTH_TOKEN}
     Content-type: application/json
```

### mqtt_plugin - Send a packet to a MQTT server

- **log_level** `debug` or `info`. Default `info`
- **active** Plugin is active. Values: `true` or `false`. Default = `true`.
- **name** Reference of an existing MQTT server configured in the top-level `mqtt_servers` configuration
- **message** Override the packet message with a custom value.
- **topic** The message topic

For example:

```
mqtt_plugin:
  name: external
  topic: meshtastic/topic
```

Placeholders can be used with the **message** value:

- `{MSG}` - Packet text

### encrypt_filter - Encrypt a packet before sending it to a MQTT server

- **log_level** `debug` or `info`. Default `info`
- **key** The PEM filename of the public key used to encrypt the message.

For example:

```
encrypt_filter:
  key: '/home/user/keys/cert.pem'
```

### decrypt_filter - Decrypt message from a MQTT server

- **log_level** `debug` or `info`. Default `info`
- **key** The PEM filename of the key used to decrypt the message.

For example:

```
decrypt_filter:
  key: '/home/user/keys/key.pem'
```

### nostr_plugin - Send a NoStr event

- **log_level** `debug` or `info`. Default `info`
- **private_key** The private key for a NoStr user. Secrets can be passed using ENV variables
- **public_key** The public key for the NoStr user associated with the private key.
- **message** A specific message (Optional)
- **relays** List of NoStr relays. Default `wss://nostr-pub.wellorder.net`, and `wss://relay.damus.io`

For example:

```
nostr_plugin:
  private_key: "{NOSTR_PRIVATE_KEY}"
  public_key: "npub1d0ja5d.......xw7jys4eqnk0"
  relays:
    - "wss://nostr-pub.wellorder.net"
```

Placeholders can be used with the **message** value:

- `{MSG}` - Packet text

### owntracks_plugin - Send location data to MQTT server for Owntracks

- **log_level** `debug` or `info`. Default `info`
- **server_name** The mqtt server to send owntracks messages to
- **tid_table** Table of the numeric from IDs of each node, mapped to an Owntracks name and TID


For example:

```
owntracks_plugin:
  server_name: external
  tid_table:
    "1234": ["Van", "GV"]
    "-5678": ["Home", "HR"]
```

Placeholders can be used with the **message** value:

- `{MSG}` - Packet text

### radio_message_plugin - Send a packet to a radio

- **log_level** `debug` or `info`. Default `info`
- **active** Plugin is active. Values: `true` or `false`. Default `true`.
- **device** Required. Send the packet to a Radio with this name. It should be configured in the top-level `devices` configuration
- **message** Send a text message
- **lat** Send a position message having this latitude
- **lng** Send a position message having this longitude
- **node_mapping** Map the packet `to` value to another value
- **to** Target node reference
- **toId** Target node reference. Ignored if `to` is used.

For example:

Broadcasts all packets to the "remote" radio network that are destined to the node `12354345`.

```
radio_message_plugin:
  device: remote
  node_mapping:
    12354345: ^all
```

## Run the bridge

### Command-line

Create a `config.yaml` in the `meshtastic-bridge` directory. Run:

```
$ source bin/activate
```

And:

```
python main.py
```

### Docker

Create a `config.yaml` with the desired settings and run the following Docker command:

#### Linux

```
docker run --rm --network host -v $(pwd)/config.yaml:/code/config.yaml gwhittington/meshtastic-bridge:latest
```

## Resources

- Example guidance for creating [PEM](https://www.suse.com/support/kb/doc/?id=000018152) key files.
- Test webhooks using [Webhooks.site](https://webhook.site/)
