# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.

import select
import logging

import pynetsim.protocols.tcp as tcp

log = logging.getLogger(__name__)


class Mirai(tcp.TCP):

    name = "mirai"

    def run(self):
        wait_count = 1
        self.send(b"\x00\x00")
        while True:
            payload = self.recv()
            if payload or wait_count % 6 == 0:
                self.send(b"\x00\x00")
                wait_count = 0
            elif not payload:
                wait_count += 1

    def recv(self):
        data = None
        s = select.select([self.socket], [], [], 10)
        if s[0]:
            data = self.socket.recv(self.recv_size)
        return data

    @classmethod
    def guess_protocol_from_payload(cls, payload, config, addr):
        """
        Iterates through known protocols to see if the payload is recognized

        :param payload: raw payload received from a connection 
        :return: Protocol object
        """
        identified_protocol = tcp.TCP
        if payload == b"\x00\x00\x00\x00":
            identified_protocol = cls
        return identified_protocol
