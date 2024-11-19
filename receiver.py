#!/usr/bin/python

import sys
from socket import *
from struct import *

if len(sys.argv) < 2:
        print "Usage: %s ifname" % sys.argv[0]
        sys.exit(0)

# Nome da interface local
ifname = sys.argv[1]

# Cria um descritor de socket do tipo RAW 
ETH_P_ALL = 0x0003
s = socket(AF_PACKET, SOCK_RAW, ntohs(ETH_P_ALL))

# Associa socket a interface local
s.bind((ifname, 0))

print "Esperando quadros ..."
while True:

    # Recebe quadros
    ret = s.recvfrom(1600)
    frame = ret[0]
     
    # Extrai conteudo do quadro Ethernet
    eth_length = 14
    eth_header = frame[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    ethertype = ntohs(eth[2])
    mac_dst = frame[0:6]
    mac_src = frame[6:12]

    if ethertype == 0x0fff:
       print "MAC destino: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(mac_dst[0]),
       ord(mac_dst[1]), ord(mac_dst[2]), ord(mac_dst[3]), ord(mac_dst[4]), ord(mac_dst[5]))
       print "MAC origem: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(mac_src[0]),
       ord(mac_src[1]), ord(mac_src[2]), ord(mac_src[3]), ord(mac_src[4]), ord(mac_src[5]))
       print "EtheType: %#06x" % ethertype
       print "Dado: %s" % frame[14:]
 

