import logging
import threading
import queue
import time
from typing import List, Dict, Optional, Any
from datetime import datetime
import netifaces
from scapy.all import sniff, get_if_list, IP, TCP, UDP, Raw, DNS, Ether, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse

logger = logging.getLogger(__name__)

class PacketData:
    def __init__(self, packet):
        self.timestamp = datetime.now()
        self.raw_packet = packet
        
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
        self.protocol = None
        self.payload_size = 0
        self.url = None
        self.dns_query = None
        self.sni = None
        self.flags = []
        
        self._parse_packet(packet)
    
    def _parse_packet(self, packet):
        if IP in packet:
            self.src_ip = packet[IP].src
            self.dst_ip = packet[IP].dst
            self.protocol = packet[IP].proto
            
            if TCP in packet:
                self.protocol = 'TCP'
                self.src_port = packet[TCP].sport
                self.dst_port = packet[TCP].dport
                self.flags = self._get_tcp_flags(packet[TCP])
                
                if packet[TCP].dport in [80, 8080] and HTTPRequest in packet:
                    self._parse_http(packet)
                
                if packet[TCP].dport == 443:
                    self._parse_tls(packet)
            
            elif UDP in packet:
                self.protocol = 'UDP'
                self.src_port = packet[UDP].sport
                self.dst_port = packet[UDP].dport
                
                if DNS in packet and packet[DNS].qr == 0:
                    self.dns_query = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
            
            elif ICMP in packet:
                self.protocol = 'ICMP'
            
            if Raw in packet:
                self.payload_size = len(packet[Raw].load)
    
    def _get_tcp_flags(self, tcp_layer) -> List[str]:
        flags = []
        if tcp_layer.flags.S: flags.append('SYN')
        if tcp_layer.flags.A: flags.append('ACK')
        if tcp_layer.flags.F: flags.append('FIN')
        if tcp_layer.flags.R: flags.append('RST')
        if tcp_layer.flags.P: flags.append('PSH')
        if tcp_layer.flags.U: flags.append('URG')
        return flags
    
    def _parse_http(self, packet):
        if HTTPRequest in packet:
            http = packet[HTTPRequest]
            host = http.Host.decode('utf-8', errors='ignore') if http.Host else ''
            path = http.Path.decode('utf-8', errors='ignore') if http.Path else '/'
            self.url = f"http://{host}{path}"
    
    def _parse_tls(self, packet):
        # Simplified TLS parsing - just identify HTTPS traffic by port
        if self.dst_port == 443:
            # For now, we'll just note it's HTTPS traffic
            # Advanced TLS/SNI parsing can be added later with proper library support
            pass
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'url': self.url,
            'dns_query': self.dns_query,
            'sni': self.sni,
            'payload_size': self.payload_size,
            'flags': self.flags
        }

class PacketSniffer:
    def __init__(self, interfaces: List[str], config: Dict):
        self.interfaces = self._validate_interfaces(interfaces)
        self.config = config
        self.is_running = False
        
        self.packet_queue = queue.Queue(
            maxsize=config.get('performance', {}).get('max_packet_queue_size', 10000)
        )
        
        self.stats = {
            'packets_captured': 0,
            'packets_processed': 0,
            'packets_dropped': 0,
            'bytes_captured': 0,
            'start_time': None
        }
        
        self._lock = threading.Lock()
        self._sniff_threads = []
        
        self.bpf_filter = self._build_bpf_filter()
        self.sampling_rate = config.get('performance', {}).get('packet_sampling_rate', 1.0)
    
    def _validate_interfaces(self, interfaces: List[str]) -> List[str]:
        available_interfaces = get_if_list()
        valid_interfaces = []
        
        for iface in interfaces:
            if iface in available_interfaces:
                valid_interfaces.append(iface)
                logger.info(f"Will monitor interface: {iface}")
            else:
                logger.warning(f"Interface {iface} not found")
        
        if not valid_interfaces:
            logger.warning("No valid interfaces found, using default")
            valid_interfaces = [available_interfaces[0]]
        
        return valid_interfaces
    
    def _build_bpf_filter(self) -> str:
        filters = []
        
        filters.append("tcp port 80 or tcp port 443 or tcp port 8080")
        
        filters.append("udp port 53")
        
        filters.append("tcp[tcpflags] & tcp-syn != 0")
        
        return " or ".join(filters) if filters else ""
    
    def start(self):
        if self.is_running:
            logger.warning("Packet sniffer is already running")
            return
        
        self.is_running = True
        self.stats['start_time'] = datetime.now()
        
        for iface in self.interfaces:
            thread = threading.Thread(
                target=self._sniff_interface,
                args=(iface,),
                name=f"sniffer_{iface}",
                daemon=True
            )
            thread.start()
            self._sniff_threads.append(thread)
        
        logger.info(f"Started packet capture on {len(self.interfaces)} interfaces")
    
    def stop(self):
        if not self.is_running:
            return
        
        logger.info("Stopping packet sniffer...")
        self.is_running = False
        
        for thread in self._sniff_threads:
            thread.join(timeout=5)
        
        self._sniff_threads.clear()
        logger.info("Packet sniffer stopped")
    
    def _sniff_interface(self, interface: str):
        try:
            logger.info(f"Starting capture on {interface} with filter: {self.bpf_filter}")
            
            sniff(
                iface=interface,
                prn=self._packet_handler,
                filter=self.bpf_filter,
                store=False,
                stop_filter=lambda _: not self.is_running
            )
            
        except Exception as e:
            logger.error(f"Error capturing on {interface}: {e}")
    
    def _packet_handler(self, packet):
        try:
            with self._lock:
                self.stats['packets_captured'] += 1
                self.stats['bytes_captured'] += len(packet)
            
            if self.sampling_rate < 1.0:
                import random
                if random.random() > self.sampling_rate:
                    return
            
            packet_data = PacketData(packet)
            
            try:
                self.packet_queue.put_nowait(packet_data)
                with self._lock:
                    self.stats['packets_processed'] += 1
            except queue.Full:
                with self._lock:
                    self.stats['packets_dropped'] += 1
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def get_packets(self, timeout: float = 1.0) -> List[PacketData]:
        packets = []
        deadline = time.time() + timeout
        
        while time.time() < deadline:
            try:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                
                packet = self.packet_queue.get(timeout=min(remaining, 0.1))
                packets.append(packet)
                
                while not self.packet_queue.empty() and len(packets) < 100:
                    packets.append(self.packet_queue.get_nowait())
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error getting packets: {e}")
                break
        
        return packets
    
    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            stats = self.stats.copy()
        
        if stats['start_time']:
            uptime = (datetime.now() - stats['start_time']).total_seconds()
            stats['uptime_seconds'] = uptime
            stats['packets_per_second'] = stats['packets_captured'] / uptime if uptime > 0 else 0
            stats['bytes_per_second'] = stats['bytes_captured'] / uptime if uptime > 0 else 0
        
        stats['queue_size'] = self.packet_queue.qsize()
        stats['interfaces'] = self.interfaces
        
        return stats
    
    def read_pcap(self, pcap_file: str) -> List[PacketData]:
        packets = []
        try:
            logger.info(f"Reading packets from {pcap_file}")
            
            pcap_packets = sniff(offline=pcap_file, filter=self.bpf_filter)
            
            for packet in pcap_packets:
                packet_data = PacketData(packet)
                packets.append(packet_data)
            
            logger.info(f"Read {len(packets)} packets from {pcap_file}")
            
        except Exception as e:
            logger.error(f"Error reading pcap file: {e}")
        
        return packets