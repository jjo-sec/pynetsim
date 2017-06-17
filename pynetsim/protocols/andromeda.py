# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.

import re
import logging
import select

from pynetsim.protocols.http import HTTP
import pynetsim.lib.core as core

log = logging.getLogger(__name__)


class Andromeda(HTTP):

    name = "andromeda"

    http_response = """HTTP/1.1 {} OK
Date: {} GMT
Server: {}
Content-Length: 0
Content-Type: text/html; charset=iso-8859-1
Connection: close


"""


    def run(self):
        log.debug(self.recv())
        response = self.http_response.format(self.config.get("http").get("response_code", 200),
                                             "",
                                             self.config.get("http").get("server_name", "Apache/2.4.18 (Ubuntu)"))
        self.send(bytes(response, encoding="utf-8"))
        self.socket.close()

    def recv(self):
        s = select.select([self.socket], [], [], 1)
        if s[0]:
            data = self.socket.recv(self.recv_size)
        else:
            data = None
        return data

    def send(self, buffer):
        self.socket.send(buffer)

    @classmethod
    def guess_protocol_from_payload(cls, payload, config, addr):
        """
        Iterates through known protocols to see if the payload is recognized

        :param payload: raw payload received from a connection
        :return: Protocol object
        """
        identified_protocol = HTTP
        if payload and payload.startswith(b"POST ") and b"\r\nUser-Agent: Mozilla/4.0":
            identified_protocol = Andromeda
            for protocol in cls.get_known_protocols(config):
                log.debug("Checking for {}".format(protocol))
                protocol_class = core.find_protocol_class(protocol)
                new_protocol = protocol_class.guess_protocol_from_payload(payload, config, addr)
                if new_protocol != identified_protocol:
                    identified_protocol = protocol_class
                    break
        return identified_protocol