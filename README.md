## Repeater

This module will sniff and record packets to/from our services. The response sent from our service will be checked to see if they contain our flag. If so, the recorded requests will be played back against our targets.

### Usage

```
usage: repeater.py [-h] --interface INTERFACE --game-address GAME_ADDRESS
						--team-token TEAM_TOKEN
```

### Example

```
sudo python3 repeater.py --interface tun0 --game-address 52.52.83.248
						--team-token 93FsTZPAo4La1tHLmuxy
```

### Detailed Description

- The module will use swpag_client to retrieve the set of services, targets, and also to submit the flags.
- Flag in request/response will be identified using the following regex *'FLG[a-zA-Z0-9]+'*
- Sniffer will run for the duration of the tick then restart to get fresh flag_ids.
- Requires root access due to running sniffer and creating raw packets.

### Dependencies

- python3
- swpag_client
- scapy