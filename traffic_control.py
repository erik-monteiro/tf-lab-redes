# traffic_control.py

import socket
import struct
import time

historico = []

def sniffer(interface):
    """Captura pacotes de rede e processa DNS e HTTP."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((interface, 0))
    print("[INFO] Iniciando sniffer... Pressione Ctrl+C para parar.")

    try:
        while True:
            packet = s.recvfrom(65535)[0]
            processar_pacote(packet)
    except KeyboardInterrupt:
        print("[INFO] Sniffer finalizado.")
        # Após o término, salva o histórico em HTML
        salvar_historico("historico.html", historico)
        print("[INFO] Histórico salvo em 'historico.html'.")

def processar_pacote(packet):
    """Processa pacotes Ethernet, IP e TCP/UDP."""
    eth_header = packet[:14]
    eth_data = struct.unpack("!6s6sH", eth_header)
    eth_type = eth_data[2]  # Já está em ordem de bytes correta

    if eth_type == 0x0800:  # IPv4
        ip_header = packet[14:34]
        ip_data = struct.unpack("!BBHHHBBH4s4s", ip_header)

        protocolo = ip_data[6]
        src_ip = socket.inet_ntoa(ip_data[8])
        dst_ip = socket.inet_ntoa(ip_data[9])

        if protocolo == 6:  # TCP
            processar_tcp(packet[34:], src_ip, dst_ip)
        elif protocolo == 17:  # UDP
            processar_udp(packet[34:], src_ip, dst_ip)

def processar_tcp(data, src_ip, dst_ip):
    """Captura pacotes HTTP."""
    if len(data) < 20:
        return  # Pacote TCP inválido
    tcp_header = data[:20]
    src_port, dst_port, seq, ack_seq, offset_reserved_flags = struct.unpack("!HHLLH", tcp_header[:14])
    offset = (offset_reserved_flags >> 12) * 4
    payload = data[offset:]

    if dst_port == 80 or src_port == 80:  # HTTP
        try:
            http_data = payload.decode("utf-8", errors="ignore")
            if "GET" in http_data or "POST" in http_data:
                # Extrai a primeira linha da requisição (linha de comando)
                request_line = http_data.split("\r\n")[0]
                url = extract_url_from_request(request_line)
                if url:
                    timestamp = time.strftime("%d/%m/%Y %H:%M:%S")
                    entry = f"{timestamp} - {src_ip} - <a href=\"{url}\">{url}</a>"
                    print(f"[HTTP] {entry}")
                    historico.append(entry)
        except Exception:
            pass

def extract_url_from_request(request_line):
    """Extrai a URL da linha de requisição HTTP."""
    parts = request_line.split()
    if len(parts) >= 2:
        method, uri = parts[0], parts[1]
        if uri.startswith("http"):
            url = uri
        else:
            url = f"http://{uri}"
        return url
    return None

def processar_udp(data, src_ip, dst_ip):
    """Captura pacotes DNS."""
    if len(data) < 8:
        return  # Pacote UDP inválido
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])
    payload = data[8:]

    if dst_port == 53 or src_port == 53:  # DNS
        try:
            query_name = extract_dns_query(payload)
            if query_name:
                timestamp = time.strftime("%d/%m/%Y %H:%M:%S")
                entry = f"{timestamp} - {src_ip} - {query_name}"
                print(f"[DNS] {entry}")
                historico.append(entry)
        except Exception:
            pass

def extract_dns_query(payload):
    """Extrai o nome da consulta DNS."""
    if len(payload) < 12:
        return None  # Payload muito curto
    transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs = struct.unpack('!HHHHHH', payload[:12])
    query = ''
    i = 12
    while i < len(payload):
        length = payload[i]
        if length == 0:
            break
        i += 1
        if i + length > len(payload):
            break  # Evita indexação fora dos limites
        query += payload[i:i+length].decode(errors='ignore') + '.'
        i += length
    return query.rstrip('.')

def salvar_historico(arquivo, historico):
    """Salva o histórico de navegação em um arquivo HTML."""
    with open(arquivo, "w") as f:
        f.write("<html><header><title>Histórico de Navegação</title></header><body><ul>\n")
        for item in historico:
            f.write(f"<li>{item}</li>\n")
        f.write("</ul></body></html>")
