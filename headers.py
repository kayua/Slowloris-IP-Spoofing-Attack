from scapy.layers.http import HTTP
from scapy.layers.inet import TCP
from scapy.layers.inet import IP


class Header:

    def __init__(self):
        pass
    def create_header_network_layer(self, tll=DEFAULT_TIME_LIFE_PACKET, source_address=DEFAULT_SOURCE_ADDRESS,
                                    destination_address=DEFAULT_DESTINATION_ADDRESS):
        network_header = IP()
        network_header.tll = tll
        network_header.src = source_address
        network_header.dst = destination_address
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

