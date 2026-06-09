# Leitor de Navegação HTTP para Arquivos PCAP

## Créditos

Este projeto foi desenvolvido a partir do software Simple Packet Sniffer, disponível em:
https://github.com/Artificial-Ryan/simple-packet-sniffer

O código foi adaptado para fins acadêmicos, com a implementação da leitura offline de arquivos PCAP e interpretação de cabeçalhos HTTP.

## Nova Funcionalidade Implementada
O software original atuava apenas na captura em tempo real, isolando informações das camadas de rede e transporte (IP e TCP/UDP). 

Esta nova versão expande o programa para atuar como uma ferramenta de **análise offline**, trazendo as seguintes melhorias:
1. **Leitura de Arquivos `.pcap`:** Permite processar logs de rede salvos previamente.
2. **Dissecação HTTP (Camada de Aplicação):** Identifica requisições na porta 80 e extrai os campos `Method`, `Host` e `Path` do cabeçalho HTTP, gerando um relatório legível de navegação.

## Pré-requisitos
Antes de executar, você precisará do Python 3 e da biblioteca Scapy instalados.

## Instruções de Execução

```bash
git clone https://github.com/milebg1/simple-packet-sniffer.git
cd simple-packet-sniffer
pip install -r requirements.txt
python packet_sniffer.py -r teste.pcap
