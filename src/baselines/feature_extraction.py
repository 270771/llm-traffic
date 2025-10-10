"""
Feature extraction module for baseline ML/DL models.
Extracts numerical features from Zeek conn.log files for traditional ML and DL models.
"""

import pandas as pd
import numpy as np
from collections import defaultdict
from datetime import datetime


class ZeekFeatureExtractor:
    """Extract features from Zeek connection logs for ML/DL models."""
    
    def __init__(self):
        # Protocol mappings
        self.protocol_map = {'tcp': 0, 'udp': 1, 'icmp': 2}
        self.conn_state_map = {
            'S0': 0, 'S1': 1, 'SF': 2, 'REJ': 3, 'S2': 4, 'S3': 5,
            'RSTO': 6, 'RSTR': 7, 'RSTOS0': 8, 'RSTRH': 9, 'SH': 10,
            'SHR': 11, 'OTH': 12
        }
        
    def parse_zeek_log(self, log_path):
        """Parse Zeek conn.log file."""
        records = []
        with open(log_path, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                fields = line.strip().split('\t')
                if len(fields) >= 22:
                    records.append(fields)
        return records
    
    def extract_flow_features(self, log_path):
        """
        Extract flow-level features from a single log file.
        Returns features for the dominant flow in the log.
        """
        records = self.parse_zeek_log(log_path)
        
        if not records:
            return self._get_default_features()
        
        # Aggregate statistics
        features = {}
        
        # Protocol distribution
        protocols = [r[6] for r in records if len(r) > 6]
        icmp_count = protocols.count('icmp')
        tcp_count = protocols.count('tcp')
        udp_count = protocols.count('udp')
        total_flows = len(records)
        
        features['icmp_ratio'] = icmp_count / total_flows if total_flows > 0 else 0
        features['tcp_ratio'] = tcp_count / total_flows if total_flows > 0 else 0
        features['udp_ratio'] = udp_count / total_flows if total_flows > 0 else 0
        
        # Connection state distribution (for TCP SYN flood detection)
        conn_states = [r[11] for r in records if len(r) > 11]
        s0_count = conn_states.count('S0')  # Failed connections
        sf_count = conn_states.count('SF')  # Successful connections
        
        features['s0_ratio'] = s0_count / total_flows if total_flows > 0 else 0
        features['sf_ratio'] = sf_count / total_flows if total_flows > 0 else 0
        features['failed_conn_ratio'] = s0_count / total_flows if total_flows > 0 else 0
        
        # Temporal features
        timestamps = [float(r[0]) for r in records if len(r) > 0]
        if timestamps:
            time_span = max(timestamps) - min(timestamps)
            features['time_span'] = time_span
            features['flow_rate'] = total_flows / max(time_span, 1)
        else:
            features['time_span'] = 0
            features['flow_rate'] = 0
        
        # Byte statistics
        orig_bytes = [int(r[9]) if r[9] != '-' else 0 for r in records if len(r) > 9]
        resp_bytes = [int(r[10]) if r[10] != '-' else 0 for r in records if len(r) > 10]
        
        features['avg_orig_bytes'] = np.mean(orig_bytes) if orig_bytes else 0
        features['avg_resp_bytes'] = np.mean(resp_bytes) if resp_bytes else 0
        features['total_orig_bytes'] = sum(orig_bytes)
        features['total_resp_bytes'] = sum(resp_bytes)
        features['byte_ratio'] = sum(orig_bytes) / max(sum(resp_bytes), 1)
        
        # Packet statistics
        orig_pkts = [int(r[16]) if r[16] != '-' else 0 for r in records if len(r) > 16]
        resp_pkts = [int(r[18]) if r[18] != '-' else 0 for r in records if len(r) > 18]
        
        features['avg_orig_pkts'] = np.mean(orig_pkts) if orig_pkts else 0
        features['avg_resp_pkts'] = np.mean(resp_pkts) if resp_pkts else 0
        features['total_orig_pkts'] = sum(orig_pkts)
        features['total_resp_pkts'] = sum(resp_pkts)
        features['pkt_ratio'] = sum(orig_pkts) / max(sum(resp_pkts), 1)
        
        # Unique IPs (diversity measure)
        src_ips = set([r[2] for r in records if len(r) > 2])
        dst_ips = set([r[4] for r in records if len(r) > 4])
        
        features['unique_src_ips'] = len(src_ips)
        features['unique_dst_ips'] = len(dst_ips)
        features['src_ip_diversity'] = len(src_ips) / total_flows if total_flows > 0 else 0
        features['dst_ip_diversity'] = len(dst_ips) / total_flows if total_flows > 0 else 0
        
        # Port statistics
        src_ports = [int(r[3]) if r[3] != '-' else 0 for r in records if len(r) > 3]
        dst_ports = [int(r[5]) if r[5] != '-' else 0 for r in records if len(r) > 5]
        
        features['unique_src_ports'] = len(set(src_ports))
        features['unique_dst_ports'] = len(set(dst_ports))
        features['avg_src_port'] = np.mean(src_ports) if src_ports else 0
        features['avg_dst_port'] = np.mean(dst_ports) if dst_ports else 0
        
        # Duration statistics
        durations = [float(r[8]) if r[8] != '-' else 0 for r in records if len(r) > 8]
        features['avg_duration'] = np.mean(durations) if durations else 0
        features['max_duration'] = max(durations) if durations else 0
        features['min_duration'] = min(durations) if durations else 0
        
        # Total flow count
        features['total_flows'] = total_flows
        
        return features
    
    def _get_default_features(self):
        """Return default feature values for empty logs."""
        return {
            'icmp_ratio': 0, 'tcp_ratio': 0, 'udp_ratio': 0,
            's0_ratio': 0, 'sf_ratio': 0, 'failed_conn_ratio': 0,
            'time_span': 0, 'flow_rate': 0,
            'avg_orig_bytes': 0, 'avg_resp_bytes': 0,
            'total_orig_bytes': 0, 'total_resp_bytes': 0, 'byte_ratio': 0,
            'avg_orig_pkts': 0, 'avg_resp_pkts': 0,
            'total_orig_pkts': 0, 'total_resp_pkts': 0, 'pkt_ratio': 0,
            'unique_src_ips': 0, 'unique_dst_ips': 0,
            'src_ip_diversity': 0, 'dst_ip_diversity': 0,
            'unique_src_ports': 0, 'unique_dst_ports': 0,
            'avg_src_port': 0, 'avg_dst_port': 0,
            'avg_duration': 0, 'max_duration': 0, 'min_duration': 0,
            'total_flows': 0
        }
    
    def extract_dataset(self, log_folder, labels_dict):
        """
        Extract features from multiple log files.
        
        Args:
            log_folder: Path to folder containing .log files
            labels_dict: Dictionary mapping filename (without .log) to boolean label
            
        Returns:
            X: Feature matrix (numpy array)
            y: Label vector (numpy array)
            filenames: List of filenames corresponding to each row
        """
        import os
        
        X_list = []
        y_list = []
        filenames = []
        
        for fname_no_ext, label in labels_dict.items():
            log_path = os.path.join(log_folder, fname_no_ext + '.log')
            
            if not os.path.exists(log_path):
                continue
            
            features = self.extract_flow_features(log_path)
            X_list.append(list(features.values()))
            y_list.append(1 if label else 0)
            filenames.append(fname_no_ext)
        
        return np.array(X_list), np.array(y_list), filenames
    
    def get_feature_names(self):
        """Return ordered list of feature names."""
        return [
            'icmp_ratio', 'tcp_ratio', 'udp_ratio',
            's0_ratio', 'sf_ratio', 'failed_conn_ratio',
            'time_span', 'flow_rate',
            'avg_orig_bytes', 'avg_resp_bytes',
            'total_orig_bytes', 'total_resp_bytes', 'byte_ratio',
            'avg_orig_pkts', 'avg_resp_pkts',
            'total_orig_pkts', 'total_resp_pkts', 'pkt_ratio',
            'unique_src_ips', 'unique_dst_ips',
            'src_ip_diversity', 'dst_ip_diversity',
            'unique_src_ports', 'unique_dst_ports',
            'avg_src_port', 'avg_dst_port',
            'avg_duration', 'max_duration', 'min_duration',
            'total_flows'
        ]


if __name__ == "__main__":
    # Test feature extraction
    extractor = ZeekFeatureExtractor()
    print("Feature names:", extractor.get_feature_names())
    print(f"Total features: {len(extractor.get_feature_names())}")
