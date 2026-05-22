from scapy.all import *
# Estas linhas abaixo são o "seguro" contra o erro de 'IP not defined'
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers import http

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"  TCP - Source Port: {src_port}, Destination Port: {dst_port}")
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"  UDP - Source Port: {src_port}, Destination Port: {dst_port}")

        if packet.haslayer(Raw):
            print(f"  Payload: {packet[Raw].load[:50]}...") # Print first 50 bytes of payload
    else:
        print(packet.summary())

print("Starting packet capture... Press Ctrl+C to stop.")

# Filter for IP packets (you can change this to 'tcp', 'udp', 'port 80', etc.)
# For more filter options, see: https://biot.com/capstats/bpf.html
packets = sniff(prn=packet_callback, count=10, filter="ip")

print("Packet capture finished.")

# Save captured packets to a pcap file
output_file = "captured_packets.pcap"
wrpcap(output_file, packets)
print(f"Captured packets saved to {output_file}")