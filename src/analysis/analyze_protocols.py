#!/usr/bin/env python3
"""Analyze protocol distribution in Zeek conn.log files"""

def analyze_log(filepath):
    tcp = icmp = udp = other = total = 0
    syn_patterns = 0
    
    with open(filepath, encoding='utf-8', errors='ignore') as f:
        # Skip header lines (starting with #)
        for line in f:
            if not line.startswith('#'):
                break
        
        # Process data lines
        for line in f:
            total += 1
            fields = line.split('\t')
            
            if len(fields) > 11:  # Need enough fields
                proto = fields[6]
                conn_state = fields[11]
                
                if proto == 'tcp':
                    tcp += 1
                    # Check for SYN flood indicators
                    if conn_state in ['S0', 'S1', 'REJ', 'RSTO', 'RSTOS0']:
                        syn_patterns += 1
                elif proto == 'icmp':
                    icmp += 1
                elif proto == 'udp':
                    udp += 1
                else:
                    other += 1
    
    print(f"\n{'='*60}")
    print(f"Protocol Analysis: {filepath}")
    print(f"{'='*60}")
    print(f"Total connections: {total:,}")
    print(f"\nBreakdown:")
    print(f"  TCP:   {tcp:,} ({tcp/total*100:.1f}%)")
    print(f"  ICMP:  {icmp:,} ({icmp/total*100:.1f}%)")
    print(f"  UDP:   {udp:,} ({udp/total*100:.1f}%)")
    print(f"  Other: {other:,} ({other/total*100:.1f}%)")
    print(f"\nSYN Flood Indicators (TCP with S0/S1/REJ/RSTO states):")
    print(f"  {syn_patterns:,} connections ({syn_patterns/tcp*100:.1f}% of TCP)")
    print(f"{'='*60}\n")
    
    return {
        'total': total,
        'tcp': tcp,
        'icmp': icmp,
        'udp': udp,
        'other': other,
        'syn_patterns': syn_patterns
    }

if __name__ == "__main__":
    stats = analyze_log('data/raw/filtered_conn110.log')
