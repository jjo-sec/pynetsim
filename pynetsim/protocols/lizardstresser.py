# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.

import select
import logging

import pynetsim.protocols.tcp as tcp

log = logging.getLogger(__name__)


class LizardStresser(tcp.TCP):

    name = "lizardstresser"

    def run(self):
        ping_count = 0
        while True:
            payload = self.recv()
            if not payload:
                # randomly send some commands to the bot
                if ping_count % 3 == 0:
                    self.send(b"GETLOCALIP")
                elif ping_count % 4 == 0:
                    self.send(b"SH /bin/ls")
                elif ping_count % 5 == 0:
                    self.send(b"LOLNOGTFO")
                else:
                    self.send(b"PING\n")
                    ping_count += 1

    def recv(self):
        payload = None
        s = select.select([self.socket], [], [], 10)
        if s[0]:
            payload = self.socket.recv(self.recv_size)
        return payload

    @classmethod
    def guess_protocol_from_payload(cls, payload, config, addr):
        """
        Iterates through known protocols to see if the payload is recognized

        :param payload: raw payload received from a connection
        :return: Protocol object
        """
        identified_protocol = tcp.TCP
        if payload.startswith(b"BUILD "):
            identified_protocol = cls
        return identified_protocol
