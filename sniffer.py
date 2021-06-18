#!/usr/bin/env python3

from os import name
import socket
import struct
import argparse

protocols_dictionary = {
    0: ['!6s6sH'],  # Ethernet Protocol
    1: ['!BBH'],  # ICMP Packets
    6: ['!2H2L2B3H'],  # TCP protocol
    8: ['!2B3H2BH4s4s'],  # Exterior Gateway Protocol (EGP)
    17: ['!HHHH']  # UDP Protocol
}


def get_eth_address(address_byte):
    source_addr = "%x:%x:%x:%x:%x:%x" % struct.unpack(
        "BBBBBB", address_byte[:6])
    destination_addr = "%x:%x:%x:%x:%x:%x" % struct.unpack(
        "BBBBBB", address_byte[6:12])

    return source_addr, destination_addr


def get_header_upacked(protocol_nunber, buffer_to_unpack):
    packet_unpacked = struct.unpack(
        protocols_dictionary[protocol_nunber][0], buffer_to_unpack)
    return packet_unpacked


def save_to_file(user_file_name, output):
    with open(user_file_name, 'a+') as f:
        f.write(output)


def main(user_options):

    if user_options.filter is not None and len(user_options.filter) > 0:
        filtered = True
    else:
        filtered = False

    if user_options.save is not None:
        save_output = user_options.save
    else:
        save_output = False

    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as socket_object:

        while True:
            result_to_print = ''
            packet = socket_object.recvfrom(30000)
            packet = packet[0]
            eth_length = 14
            eth_header = packet[:eth_length]
            eth = get_header_upacked(0, eth_header)
            eth_protocol = socket.ntohs(eth[2])
            source_mac, destination_mac = get_eth_address(packet[:12])

            result_to_print = f'''
            Destination MAC2: {destination_mac}
            Source MAC2: {source_mac}
            Protocol: {str(eth_protocol)}'''

            # The Exterior Gateway Protocol (EGP) is a routing protocol for the Internet
            if eth_protocol == 8:
                ip_header = packet[eth_length:20 + eth_length]
                ip_header_unpacked = get_header_upacked(
                    eth_protocol, ip_header)
                ip_version_len = ip_header_unpacked[0]
                ip_version = ip_version_len >> 4
                ip_header_len = (ip_version_len & 0xF) * 4

                ip_ttl = ip_header_unpacked[5]
                protocol = ip_header_unpacked[6]
                source_addr = socket.inet_ntoa(ip_header_unpacked[8])
                destination_addr = socket.inet_ntoa(ip_header_unpacked[9])
                result_to_print += f'''
                    -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
                    Version : {str(ip_version)} IP Header Length : {str(ip_header_len)}
                    TTL : {str(ip_ttl)} Protocol : {str(protocol)}
                    Source Address : {str(source_addr)}
                    Destination Address : {str(destination_addr)}
                '''

                # TCP protocol
                if protocol == 6:
                    if (filtered and 't' not in user_options.filter):
                        continue
                    tcp = ip_header_len + eth_length
                    tcp_header = packet[tcp: tcp + 20]
                    tcp_header_unpacked = get_header_upacked(
                        protocol, tcp_header)

                    source_port = tcp_header_unpacked[0]
                    dest_port = tcp_header_unpacked[1]
                    sequence = tcp_header_unpacked[2]
                    acknowledgement = tcp_header_unpacked[3]
                    tcp_header_length = (tcp_header_unpacked[4] >> 4) * 4
                    reserved = tcp_header_unpacked[4] & 0xF

                    header_size = eth_length + ip_header_len + tcp_header_length * 4
                    data_size = len(packet) - header_size

                    data = packet[header_size:]

                    result_to_print += f'''
                        Protocol number: 6 TCP
                        Source Port : {str(source_port)} Dest Port : {str(dest_port)}
                        Sequence Number: {str(sequence)} Acknowledgement: {str(acknowledgement)}
                        CP header length: {str(tcp_header_length)}
                        Reserverd: {reserved}
                        Data: {data}
                        -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
                    '''
                    print(result_to_print)

                    if save_output:
                        save_to_file('log.txt', result_to_print)

                # ICMP Packets
                # The Internet Control Message Protocol (ICMP) is a supporting protocol in the Internet protocol suite.
                elif protocol == 1:
                    if (filtered and 'i' not in user_options.filter):
                        continue
                    icmp = ip_header_len + eth_length
                    icmp_header_length = 4
                    icmp_header = packet[icmp:icmp + 4]
                    icmp_header = get_header_upacked(protocol, icmp_header)
                    icmp_type = icmp_header[0]
                    code = icmp_header[1]
                    checksum = icmp_header[2]

                    header_size = eth_length + ip_header_len + icmp_header_length
                    data_size = len(packet) - header_size

                    data = packet[header_size:]

                    result_to_print += f'''
                        Protocol number: 1 The Internet Control Message Protocol (ICMP)
                        Type : {str(icmp_type)}
                        Code : {str(code)}
                        Checksum : {str(checksum)}
                        Data: {data}
                        -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
                    '''
                    print(result_to_print)
                    if save_output:
                        save_to_file('log.txt', result_to_print)

                # UDP packets
                elif protocol == 17:
                    if (filtered and 'u' not in user_options.filter):
                        continue
                    udp = ip_header_len + eth_length
                    udp_header_length = 8
                    udp_header = packet[udp:udp + 8]
                    udp_header = get_header_upacked(protocol, udp_header)
                    source_port = udp_header[0]
                    dest_port = udp_header[1]
                    length = udp_header[2]
                    checksum = udp_header[3]

                    header_size = eth_length + ip_header_len + udp_header_length
                    data_size = len(packet) - header_size

                    data = packet[header_size:]

                    result_to_print += f'''
                        Protocol number: 17 UDP Packets
                        Source Port : {str(source_port)}
                        Dest Port : {str(dest_port)}
                        Length : {str(length)}
                        Checksum : {str(checksum)}
                        Data size: {data_size}
                        Data: {data}
                        -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
                        '''
                    print(result_to_print)
                    if save_output:
                        save_to_file('log.txt', result_to_print)

                # some other IP packet like IGMP
                else:
                    if filtered:
                        continue
                    # print('Protocol other than TCP/UDP/ICMP')
                    result_to_print += 'Protocol other than TCP/UDP/ICMP'
                    print(result_to_print)
                    if save_output:
                        save_to_file('log.txt', result_to_print)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--filter', nargs='*', choices=['t', 'u', 'i'], help='''Filter by protocols (T)CP, (U)DP, (I)CMP. \n
        \n e.g. sniffer.py --filter t u''')
    parser.add_argument('-s', '--save', action='store_true',
                        help='Automatically save the output as log.txt')
    args = parser.parse_args()

    try:
        main(args)
    except KeyboardInterrupt:
        print('Script interrupted by the user')
        print('Bye')
