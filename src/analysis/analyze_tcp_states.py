#!/usr/bin/env python3
"""Analyze all TCP connection states in the raw log"""

syn_states = ['S0', 'S1', 'REJ', 'RSTO', 'RSTOS0']
normal_states = ['SF', 'S2', 'S3', 'OTH', 'RSTR']

tcp_syn = 0
tcp_normal = 0
tcp_other_states = {}
icmp = 0
udp = 0
other_proto = 0

with open('data/raw/filtered_conn110.log', 'r') as f:
    for line in f:
        if line.startswith('#') or not line.strip():
            continue
        
        fields = line.strip().split('\t')
        if len(fields) < 22:
            continue
        
        proto = fields[6]
        conn_state = fields[11]
        
        if proto == 'tcp':
            if conn_state in syn_states:
                tcp_syn += 1
            elif conn_state in normal_states:
                tcp_normal += 1
            else:
                tcp_other_states[conn_state] = tcp_other_states.get(conn_state, 0) + 1
        elif proto == 'icmp':
            icmp += 1
        elif proto == 'udp':
            udp += 1
        else:
            other_proto += 1

print(f"\n📊 Connection Analysis:")
print(f"   TCP SYN flood states (S0/S1/REJ/RSTO/RSTOS0): {tcp_syn}")
print(f"   TCP normal states (SF/S2/S3/OTH/RSTR): {tcp_normal}")
print(f"   TCP other states: {sum(tcp_other_states.values())}")
for state, count in sorted(tcp_other_states.items()):
    print(f"      {state}: {count}")
print(f"   ICMP: {icmp}")
print(f"   UDP: {udp}")
print(f"   Other protocols: {other_proto}")
print(f"\n   Total: {tcp_syn + tcp_normal + sum(tcp_other_states.values()) + icmp + udp + other_proto}")
