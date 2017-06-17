# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.

import socket
import logging
import random
import time

import dpkt.dns
import dpkt.dpkt

import pynetsim.protocols.tcp as tcp
import struct

log = logging.getLogger(__name__)


class TCPDNS(tcp.TCP):

    name = "tcpdns"

    def run(self):
        length, = struct.unpack_from("!H", self.payload)
        dns_payload = self.payload[2:]
        dns_query = dpkt.dns.DNS(dns_payload)
        raw_dns = self.craft_dns_response(dns_query)
        tcp_dns_payload = struct.pack("!H{}s".format(len(raw_dns)), len(raw_dns), raw_dns)
        self.send(tcp_dns_payload)
        self.socket.close()

    def send(self, data_buffer):
        if data_buffer:
            self.socket.send(data_buffer)

    def craft_dns_response(self, dns_query):
        dns_response = None
        log.debug(dns_query.qd[0].name)
        if dns_query.qr == dpkt.dns.DNS_Q and dns_query.opcode == dpkt.dns.DNS_QUERY:
            if len(dns_query.qd) == 1 and dns_query.qd[0].type == dpkt.dns.DNS_A:
                dns_response = dns_query
                dns_response.op = dpkt.dns.DNS_RA
                dns_response.rcode = dpkt.dns.DNS_RCODE_NOERR
                dns_response.qr = dpkt.dns.DNS_R
                arr = dpkt.dns.DNS.RR()
                arr.cls = dpkt.dns.DNS_IN
                arr.type = dpkt.dns.DNS_A
                arr.name = dns_query.qd[0].name
                arr.ip = socket.inet_aton(self.get_response_ip())
                dns_response.an.append(arr)
            elif len(dns_query.qd) == 1 and dns_query.qd[0].type == dpkt.dns.DNS_MX:
                dns_response = dns_query
                dns_response.op = dpkt.dns.DNS_RA
                dns_response.rcode = dpkt.dns.DNS_RCODE_NOERR
                dns_response.qr = dpkt.dns.DNS_R
                for i in range(self.get_num_mailservers()):
                    arr = dpkt.dns.DNS.RR()
                    arr.cls = dpkt.dns.DNS_IN
                    arr.type = dpkt.dns.DNS_MX
                    arr.name = dns_query.qd[0].name
                    arr.preference = 10*(i+1)
                    arr.mxname = "smtp{}.{}".format(i+1, dns_query.qd[0].name)
                    dns_response.an.append(arr)
            elif len(dns_query.qd) == 1 and dns_query.qd[0].type == dpkt.dns.DNS_AAAA:
                dns_response = dns_query
                dns_response.op = dpkt.dns.DNS_RA
                dns_response.rcode = dpkt.dns.DNS_RCODE_NOERR
                dns_response.qr = dpkt.dns.DNS_R
                arr = dpkt.dns.DNS.RR()
                arr.cls = dpkt.dns.DNS_IN
                arr.type = dpkt.dns.DNS_AAAA
                arr.name = dns_query.qd[0].name
                arr.ip6 = socket.inet_pton(socket.AF_INET6, "2001:1938:26f:1:204:4bff:0:1")
                dns_response.an.append(arr)
            elif len(dns_query.qd) == 1 and dns_query.qd[0].type == dpkt.dns.DNS_TXT:
                dns_response = dns_query
                dns_response.op = dpkt.dns.DNS_RA
                dns_response.rcode = dpkt.dns.DNS_RCODE_NOERR
                dns_response.qr = dpkt.dns.DNS_R
                arr = dpkt.dns.DNS.RR()
                arr.cls = dpkt.dns.DNS_IN
                arr.type = dpkt.dns.DNS_TXT
                arr.name = dns_query.qd[0].name
                # dpkt issue in python3 currently prevents setting text
                arr.text = ""
                dns_response.an.append(arr)
            elif len(dns_query.qd) == 1 and dns_query.qd[0].type == dpkt.dns.DNS_PTR:
                dns_response = dns_query
                dns_response.op = dpkt.dns.DNS_RA
                dns_response.rcode = dpkt.dns.DNS_RCODE_NXDOMAIN
                dns_response.qr = dpkt.dns.DNS_R
                arr = dpkt.dns.DNS.RR()
                arr.cls = dpkt.dns.DNS_IN
                arr.type = dpkt.dns.DNS_PTR
                dns_response.an.append(arr)
        dns_response = bytes(dns_response) if dns_response else dns_response
        return dns_response


    @classmethod
    def guess_protocol_from_payload(cls, payload, config, addr):
        identified_protocol = tcp.TCP
        try:
            length, = struct.unpack_from("!H", payload)
            log.debug(length)
            dns_payload = payload[2:]
            dns_query = dpkt.dns.DNS(dns_payload)
            if length + 2 == len(payload):
                identified_protocol = cls
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as e:
            log.exception(e)
        except Exception as e:
            log.exception(e)
        return identified_protocol

    def get_num_mailservers(self):
        return self.config.get("dns").get("mailserver_count", 3)

    def get_response_ip(self):
        random.seed(time.time())
        response_type = self.config.get("dns").get("response_type", "random")
        if response_type == "random":
            first_octet = random.randint(1,255)
            while first_octet in [10, 176, 192]:
                first_octet = random.randint(1, 255)
            response_ip = "{:d}.{:d}.{:d}.{:d}".format(first_octet,
                                                       random.randint(0,255),
                                                       random.randint(0,255),
                                                       random.randint(1,254))
        elif response_type == "hardcoded":
            response_ip = self.config.get("dns").get("default_ip", "1.2.3.4")
        else:
            log.warning("Unknown response type: {}")
            response_ip = None
        return response_ip