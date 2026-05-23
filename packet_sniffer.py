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

def main():
    parser = argparse.ArgumentParser(description="Leitor de pacotes a partir de arquivo PCAP")
    parser.add_argument("-r", "--read", required=True, help="Caminho do arquivo .pcap")
    args = parser.parse_args()

    print(f"Iniciando leitura do arquivo PCAP: {args.read}")

    sniff(
        offline=args.read,
        prn=packet_callback,
        store=False
    )

    print("Leitura do arquivo PCAP finalizada.")


if __name__ == "__main__":
   main()