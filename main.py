from random import randint

from scapy.layers.http import HTTP
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.sendrecv import send

DEFAULT_HTTP_VERSION = 2.0
DEFAULT_SOURCE_ADDRESS = '127.0.0.1'
DEFAULT_DESTINATION_ADDRESS = '127.0.0.1'
DEFAULT_TIME_LIFE_PACKET = 10
DEFAULT_SOURCE_PORT = 80
DEFAULT_DESTINATION_PORT = 80
DEFAULT_NUMBER_RANDOM_ADDRESS = 100


def create_header_network_layer(tll=DEFAULT_TIME_LIFE_PACKET, source_address=DEFAULT_SOURCE_ADDRESS,
                                destination_address=DEFAULT_DESTINATION_ADDRESS):
    network_header = IP()
    network_header.tll = tll
    network_header.src = source_address
    network_header.dst = destination_address
    return network_header


def create_header_transport_layer(ip_header=None, source_port=DEFAULT_SOURCE_PORT,
                                  destination_port=DEFAULT_DESTINATION_PORT):
    transport_header = ip_header / TCP()
    transport_header.dport = destination_port
    transport_header.sport = source_port
    return transport_header


def create_header_application_layer(transport_header=None, requisition=None, internal=1):
    application_header = transport_header / HTTP(requisition)
    application_header.internal = internal
    return application_header


def create_spoofing_packet(requisition, version=2.0):
    spoofing_packet = "GET /{} HTTP/{} \n\n".format(requisition, version)
    spoofing_packet = bytes(spoofing_packet, "utf-8")
    return spoofing_packet


def get_random_address_list(number_address=DEFAULT_NUMBER_RANDOM_ADDRESS):
    list_address = [[randint(0, 255), randint(0, 255), randint(0, 255), randint(0, 255)] for i in range(number_address)]
    list_address = ['.'.join(list(map(str, i))) for i in list_address]
    return list_address


# packet_requisition = create_spoofing_packet('')

# packet_spoofing = create_header_network_layer(source_address='192.168.1.103', destination_address='200.132.146.44')
# packet_spoofing = create_header_transport_layer(packet_spoofing)
# packet_spoofing = create_header_application_layer(packet_spoofing, packet_requisition)

random_address = get_random_address_list(5)
print(random_address)
# send(packet_spoofing * 1)
