#!/usr/bin/python

import sys
import fcntl
from socket import *

if len(sys.argv) < 2:
	print "Usage: %s ifname" % sys.argv[0]
	sys.exit(0)

# Nome da interface local
ifname = sys.argv[1]

# Cria um descritor de socket do tipo RAW
s = socket(AF_PACKET, SOCK_RAW)

# Associa socket a interface local
s.bind((ifname, 0))

# Obtem o endereco MAC da interface local
SIOCGIFHWADDR = 0x8927
ifr = ifname + '\0'*(32-len(ifname))
r = fcntl.ioctl(s.fileno(),SIOCGIFHWADDR,ifr)
mac = r[18:24]

# Preenche os campos do cabecalho Ethernet

# Endereco MAC de destino
dst_addr = "\xff\xff\xff\xff\xff\xff"

# Endereco MAC de origem
src_addr = mac

# EtherType
ethertype = "\xff\x0f" #htons(0x0fff)

# Obtem uma mensagem do usuario
print "Digite a mensagem: "
data = sys.stdin.readline()

# Monta o quadro Ethernet
frame = dst_addr+src_addr+ethertype+data

# Envia o quadro Ethernet
s.send(frame)

print "Pacote enviado."

