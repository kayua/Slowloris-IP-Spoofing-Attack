from scapy.layers.http import HTTP
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send

DEFAULT_HTTP_VERSION = 2.0
DEFAULT_SOURCE_ADDRESS = '127.0.0.1'
DEFAULT_DESTINATION_ADDRESS = '127.0.0.1'
DEFAULT_TIME_LIFE_PACKET = 10


def create_header_network_layer(tll=DEFAULT_TIME_LIFE_PACKET, source_address=DEFAULT_SOURCE_ADDRESS,
                                destination_address=DEFAULT_DESTINATION_ADDRESS):
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


def create_spoofing_packet(requisition):
    spoofing_packet = "GET /{} HTTP/2.0 \n\n".format(requisition)
    spoofing_packet = bytes(spoofing_packet, "utf-8")
    return spoofing_packet


packet_requisition = create_spoofing_packet('')

packet_spoofing = create_header_network_layer(source_address='192.168.1.103', destination_address='200.132.146.44')
packet_spoofing = create_header_transport_layer(packet_spoofing)
packet_spoofing = create_header_application_layer(packet_spoofing, packet_requisition)

send(packet_spoofing * 1)
