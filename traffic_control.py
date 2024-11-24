import socket
import struct

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

def processar_pacote(packet):
    """Processa pacotes Ethernet, IP e TCP/UDP."""
    eth_header = packet[:14]
    eth_data = struct.unpack("!6s6sH", eth_header)

    if eth_data[2] == 0x0800:  # IPv4
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
    src_port, dst_port, _, _, offset_flags = struct.unpack("!HHLLH", data[:14])
    offset = (offset_flags >> 12) * 4
    payload = data[offset:]

    if dst_port == 80 or src_port == 80:  # HTTP
        try:
            http_data = payload.decode("utf-8", errors="ignore")
            if "GET" in http_data or "POST" in http_data:
                print(f"[HTTP] {src_ip} -> {dst_ip}")
                print(http_data.split("\r\n")[0])  # Primeira linha da requisição
        except Exception:
            pass

def processar_udp(data, src_ip, dst_ip):
    """Captura pacotes DNS."""
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])
    payload = data[8:]

    if dst_port == 53 or src_port == 53:  # DNS
        try:
            query_name = extract_dns_query(payload)
            print(f"[DNS] {src_ip} -> {dst_ip}: {query_name}")
        except Exception:
            pass

def extract_dns_query(payload):
    """Extrai o nome da consulta DNS."""
    query = []
    i = 12  # Pula o cabeçalho DNS
    while payload[i] != 0:
        length = payload[i]
        i += 1
        query.append(payload[i:i+length].decode())
        i += length
    return ".".join(query)

def salvar_historico(arquivo, historico):
    # Salva o histórico de navegação em HTML
    with open(arquivo, "w") as f:
        f.write("<html><header><title>Histórico</title></header><body><ul>")
        for item in historico:
            f.write(f"<li>{item}</li>")
        f.write("</ul></body></html>")
