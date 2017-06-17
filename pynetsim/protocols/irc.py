# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.

import time
import logging

from pynetsim.protocols.tcp import TCP

log = logging.getLogger(__name__)


class IRC(TCP):

    name = "irc"

    proto_commands = dict(NICK=""":irc.pynets.im NOTICE AUTH :*** Looking up your hostname...\r\n:irc.pynets.im NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead\r\n""",
                          JOIN="""""",
                          NAMES="""""",
                          PART=""""""
                          )

    def run(self):
        load = self.payload
        while load:
            try:
                if load:
                    responses = self.get_responses(load)
                    if responses:
                        for response in responses:
                            self.send(response)
                            load = self.recv()
                            log.debug(load)
                    else:
                        load = self.recv()
                        log.debug(load)
            except Exception as e:
                log.exception(e)
                break
        # attempt to temp hang the client to keep them from exiting prematurely
        time.sleep(30)
        self.socket.close()

    def get_responses(self, payload):
        responses = []
        command_parts = payload.decode("utf-8").strip().split(" ")
        command = command_parts[0]
        if len(command_parts) == 2:
            command_val = command_parts[1]
            self.set_proto_var(command, command_val)
        command_us = payload.decode("utf-8").strip().replace(" ", "_")
        log.debug(command)
        log.debug(command_us)
        for req, res in self.proto_commands.items():
            if command == req:
                for response in self.get_proto_command(command, []):
                    log.debug(response)
                    responses.append(bytes(response.format(**self.proto_vars), encoding="ascii"))
                break
            elif command_us == req:
                for response in self.get_proto_command(command_us, []):
                    responses.append(bytes(response.format(**self.proto_vars), encoding="ascii"))
                break
        return responses

    def recv(self):
        return self.socket.recv(self.recv_size)

    def send(self, buffer):
        self.socket.send(buffer)

    def send_ping(self):
        pass

    @classmethod
    def guess_protocol_from_payload(cls, payload, config, addr):
        """
        Iterates through known protocols to see if the payload is recognized

        :param payload: raw payload received from a connection
        :param config: configuration object
        :param addr: connection address

        :return: Protocol object
        """
        identified_protocol = TCP
        if payload.startswith((b"NICK ", b"USER ", b"CAP ")):
            identified_protocol = IRC
        return identified_protocol
