from scapy.layers.http import HTTP
from scapy.layers.inet import TCP
from scapy.layers.inet import IP


class Header:

    def __init__(self, time_life_packet, source_address, destination_address, source_port, destination_port, internal=1):

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

    def create_header_transport_layer(self, ip_header=None):
        transport_header = ip_header / TCP()
        transport_header.dport = self.destination_port
        transport_header.sport = self.source_port
        return transport_header

    def create_header_application_layer(self, transport_header=None, requisition=None):
        application_header = transport_header / HTTP(requisition)
        application_header.internal = self.internal
        return application_header

    def set_source_address(self, new_address):
        self.source_address = new_address
