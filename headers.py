from scapy.layers.http import HTTP
from scapy.layers.inet import TCP
from scapy.layers.inet import IP

from main import DEFAULT_TIME_LIFE_PACKET
from main import DEFAULT_DESTINATION_PORT
from main import DEFAULT_SOURCE_ADDRESS
from main import DEFAULT_DESTINATION_ADDRESS
from main import DEFAULT_SOURCE_PORT


class Header:

    def __init__(self, time_life_packet=DEFAULT_TIME_LIFE_PACKET, source_address=DEFAULT_SOURCE_ADDRESS,
                 destination_address=DEFAULT_DESTINATION_ADDRESS, source_port=DEFAULT_SOURCE_PORT,
                 destination_port=DEFAULT_DESTINATION_PORT, internal=1):

        self.time_life_packet = time_life_packet
        self.source_address = source_address
        self.destination_address = destination_address
        self.source_port = source_port
        self.destination_port = destination_port
        self.internal = internal
        pass

    def create_header_network_layer(self):
        network_header = IP()
        network_header.tll = self.time_life_packet
        network_header.src = self.source_address
        network_header.dst = self.destination_address
        return network_header

    def create_header_transport_layer(self, ip_header=None, source_port=DEFAULT_SOURCE_PORT,
                                      destination_port=DEFAULT_DESTINATION_PORT):
        transport_header = ip_header / TCP()
        transport_header.dport = destination_port
        transport_header.sport = source_port
        return transport_header

    def create_header_application_layer(self, transport_header=None, requisition=None, internal=1):
        application_header = transport_header / HTTP(requisition)
        application_header.internal = internal
        return application_header
