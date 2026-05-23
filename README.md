# Leitor de Navegação HTTP para Arquivos PCAP

Este projeto é uma extensão do software original [Simple Packet Sniffer](https://github.com/Artificial-Ryan/simple-packet-sniffer), desenvolvido como requisito para a disciplina de Redes de Computadores.

## Nova Funcionalidade Implementada
O software original atuava apenas na captura em tempo real, isolando informações das camadas de rede e transporte (IP e TCP/UDP). 

Esta nova versão expande o programa para atuar como uma ferramenta de **análise offline**, trazendo as seguintes melhorias:
1. **Leitura de Arquivos `.pcap`:** Permite processar logs de rede salvos previamente.
2. **Dissecação HTTP (Camada de Aplicação):** Identifica requisições na porta 80 e extrai os campos `Method`, `Host` e `Path` do cabeçalho HTTP, gerando um relatório legível de navegação.

## Pré-requisitos
Antes de executar, você precisará do Python 3 e da biblioteca Scapy instalados.

```bash
pip install scapy