import random

from scapy.layers.http import HTTP
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send






packet = IP(ttl=10)
packet.src = '10.10.10.10'
packet.dst = '10.10.10.10'

packet = packet/TCP()
b = "GET /?{} HTTP/1.1".format(random.randint(0, 2000))
b = bytes(b, "utf-8")
packet = packet/HTTP(b)
send(packet*10)