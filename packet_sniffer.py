from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import argparse
import sys

requisicoes_http = []

def analisar_http(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        tcp = packet[TCP]

        if tcp.sport == 80 or tcp.dport == 80:
            payload = packet[Raw].load.decode("utf-8", errors="ignore")

            if "HTTP" in payload or payload.startswith(("GET", "POST", "HEAD")):
                linhas = payload.split("\r\n")
                primeira_linha = linhas[0] if len(linhas) > 0 else ""

                if primeira_linha.startswith(("GET", "POST", "HEAD")):
                    partes = primeira_linha.split()

                    metodo = partes[0] if len(partes) > 0 else "-"
                    recurso = partes[1] if len(partes) > 1 else "-"

                    host = "Não identificado"

                    for linha in linhas:
                        if linha.lower().startswith("host:"):
                            host = linha.split(":", 1)[1].strip()
                            break

                    requisicoes_http.append(f"[NAVEGAÇÃO] Site: {host} | Ação: {metodo} | Recurso: {recurso}")

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        analisar_http(packet)

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
            print(f"  Payload: {packet[Raw].load[:50]}...")
    else:
        print(packet.summary())

def exibir_relatorio_final():
    print("\n" + "="*50)
    print("Leitura do arquivo PCAP finalizada.")
    print("="*50)
    
    print(f"\n[RESUMO HTTP FINAL] Total de requisições de navegação detectadas: {len(requisicoes_http)}")
    if requisicoes_http:
        print("-" * 50)
        for http_info in requisicoes_http:
            print(http_info)
        print("-" * 50)
    else:
        print("Nenhum tráfego HTTP (porta 80) válido foi detectado neste arquivo.")

def main():
    parser = argparse.ArgumentParser(description="Leitor de pacotes a partir de arquivo PCAP")
    parser.add_argument("-r", "--read", required=True, help="Caminho do arquivo .pcap")
    args = parser.parse_args()

    print(f"Iniciando leitura completa do arquivo PCAP: {args.read}\n")

    sniff(
        offline=args.read,
        prn=packet_callback,
        count=2000,
        store=False
    )
    exibir_relatorio_final()

if __name__ == "__main__":
   main()