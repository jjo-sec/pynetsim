# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.

import socket
import logging
import random
import time

import dpkt.dns
import dpkt.dpkt

import pynetsim.protocols.udp as udp

log = logging.getLogger(__name__)


class DNS(udp.UDP):

    name = "dns"

    def run(self):
        dns_query = dpkt.dns.DNS(self.payload)

        self.send(self.craft_dns_response(dns_query))

    def send(self, data_buffer):
        #log.debug("Sending {}".format(data_buffer))
        if data_buffer:
            self.socket.sendto(data_buffer, self.addr)

    def craft_dns_response(self, dns_query):
        dns_response = None
        log.debug("Queried name is {}".format(dns_query.qd[0].name))
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
                arr.text = "pynetsim"
                dns_response.an.append(arr)
            elif len(dns_query.qd) == 1 and dns_query.qd[0].type == dpkt.dns.DNS_PTR:
                dns_response = dns_query
                dns_response.op = dpkt.dns.DNS_RA
                dns_response.rcode = dpkt.dns.DNS_RCODE_NXDOMAIN
                dns_response.qr = dpkt.dns.DNS_R
                arr = dpkt.dns.DNS.RR()
                arr.cls = dpkt.dns.DNS_IN
                arr.type = dpkt.dns.DNS_PTR
                # dpkt issue in python3 currently prevents setting text
                dns_response.an.append(arr)
        dns_response = bytes(dns_response) if dns_response else dns_response
        return dns_response

    @classmethod
    def guess_protocol_from_payload(cls, payload, config, addr):
        protocol = udp.UDP
        try:
            dns_query = dpkt.dns.DNS(payload)
            if hasattr(dns_query, "qd") and len(dns_query.qd) > 0:
                protocol = cls
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            pass
        return protocol

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
        elif response_type == "real":
            log.error("Unsupported")
            response_ip = None
        else:
            log.warning("Unknown response type: {}")
            response_ip = None
        return response_ip