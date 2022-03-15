import random

from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send


def create_header_network_layer(tll=10, source_address='127.0.0.1', destination_address='127.0.0.1'):
    network_header = IP()
    network_header.tll = tll
    network_header.src = source_address
    network_header.dst = destination_address
    return network_header


def create_header_transport_layer(ip_header=None, source_port=80, destination_port=80):
    transport_header = ip_header / TCP()
    transport_header.dport = destination_port
    transport_header.sport = source_port
    return transport_header


def create_header_application_layer(transport_header=None, requisition=None, internal=1):
    application_header = transport_header / HTTP(requisition)
    application_header.internal = internal
    return application_header




b = "GET /index.html HTTP/2.0 \n\n"
b = bytes(b, "utf-8")

packet_spoofing = create_header_network_layer(source_address='192.168.1.103', destination_address='172.217.29.4')
packet_spoofing = create_header_transport_layer(packet_spoofing)
packet_spoofing = create_header_application_layer(packet_spoofing, b)

send(packet_spoofing)
