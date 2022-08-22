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
         - send_plugin:
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

| Plugin            | Description                                                          |
| ----------------- | -------------------------------------------------------------------- |
| `debugger`        | Log the packet to the system console                                 |
| `message_filter`  | Filters out packets from the bridge that match a specific criteria   |
| `distance_filter` | Filters out packets that originate too far from a specified `device` |
| `webhook`         | Send HTTP requests with custom payloads using packet information     |
| `mqtt_plugin`     | Send packets to a MQTT server                                        |
| `encrypt_filter`  | Encrypt a packet for a desired MQTT recipient                        |
| `decrypt_filter`  | Decrypt a packet originating from MQTT                               |
| `send_plugin`     | Send a packet to a specified `device`                                |

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

For example:

```
message_filter:
  app:
     allow:
        - !bd5ba0ec
        - !f85bc0bc
     disallow:
        - !c15ba2ec
```

### distance_filter - Allow or block packets based on distance from origin to radio

- **log_level** `debug` or `info`. Default `info`
- **max_distance_km** Number of kilometers

For example:

```
distance_filter:
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
- **message** Override the packet message with a custom value
- **topic** The message topic

For example:

```
mqtt_plugin:
  name: external
  topic: meshtastic/topic
```

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

### send_plugin - Send a packet to a radio

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
send_plugin:
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

```
docker run -v $(pwd)/config.yaml:/code/config.yaml gwhittington/meshtastic-bridge:latest
```

## Resources

- Example guidance for creating [PEM](https://www.suse.com/support/kb/doc/?id=000018152) key files.
