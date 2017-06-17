# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.

import re
import logging
import select
import datetime

import pynetsim.protocols.http as http
import pynetsim.lib.core as core

log = logging.getLogger(__name__)


class Drive(http.HTTP):

    name = "drive"

    http_response = """HTTP/1.1 {} OK
Date: {} GMT
Server: {}
Content-Length: {}
Content-Type: text/html; charset=iso-8859-1
Connection: close

{}
"""

    drive_regex = re.compile(r"\r\n\r\nk=[A-Za-z0-9]{15}$")

    def run(self):
        log.debug(self.recv())
        response = self.http_response.format(200,
                                             datetime.datetime.now().strftime("%a, %d %B %Y %H:%m:%S GMT"),
                                             self.config.get("drive").get("server_name", "Apache/2.4.18 (Ubuntu)"),
                                             len(self.config.get("drive").get("response", "")),
                                             self.config.get("drive").get("response", "")
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

    def send(self, buffer):
        self.socket.send(buffer)

    @classmethod
    def guess_protocol_from_payload(cls, payload, config, addr):
        """
        Iterates through known protocols to see if the payload is recognized

        :param payload: raw payload received from a connection
        :return: Protocol object
        """
        identified_protocol = http.HTTP
        if payload.startswith(b"POST ") and cls.drive_regex.search(payload.decode("utf-8", errors="ignore")):
            identified_protocol = cls
        return identified_protocol