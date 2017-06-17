# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.

import re
import logging
import select
import datetime

import pynetsim.protocols.tcp as tcp
import pynetsim.lib.core as core

log = logging.getLogger(__name__)


class HTTP(tcp.TCP):

    name = "http"

    http_regex = re.compile(r"^(get|put|options|post)[ \t]+[^ \t]+[ \t]+HTTP/", flags=re.IGNORECASE)
    http_response = """HTTP/1.1 {} OK
Date: {}
Server: {}
Content-Length: {}
Content-Type: text/html; charset=iso-8859-1
Connection: close

{}
"""

    def run(self):
        log.debug(self.recv())
        response = self.http_response.format(self.config.get("http").get("response_code", 200),
                                             datetime.datetime.now().strftime("%a, %d %B %Y %H:%m:%S GMT"),
                                             self.config.get("http").get("server_name", "Apache/2.4.18 (Ubuntu)"),
                                             len(self.config.get("http").get("response", "")),
                                             self.config.get("http").get("response", "")
                                             )
        self.send(bytes(response, encoding="utf-8"))
        self.socket.close()

    def recv(self):
        s = select.select([self.socket], [], [], 1)
        if s[0]:
            data = self.socket.recv(self.recv_size)
        else:
            data = None
        return data

    @classmethod
    def guess_protocol_from_payload(cls, payload, config, addr):
        """
        Iterates through known protocols to see if the payload is recognized

        :param payload: raw payload received from a connection 
        :return: Protocol object
        """
        identified_protocol = tcp.TCP
        if payload and cls.http_regex.match(payload.decode('utf-8', errors="ignore")):
            identified_protocol = HTTP
            for protocol in cls.get_known_protocols(config):
                log.debug("Checking for {}".format(protocol))
                protocol_class = core.find_protocol_class(protocol)
                new_protocol = protocol_class.guess_protocol_from_payload(payload, config, addr)
                log.debug(new_protocol)
                if new_protocol != identified_protocol:
                    log.debug("New sub-protocol detected: {}".format(new_protocol.name))
                    identified_protocol = new_protocol
                    break
        return identified_protocol