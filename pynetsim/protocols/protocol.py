# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.

import select
import logging

import pynetsim.lib.core as core

log = logging.getLogger(__name__)


class BotWhisperer(object):

    name = "dummy"

    proto_vars = dict()
    proto_commands = dict()

    def __init__(self, config, socket, addr, payload=None):
        self.config = config
        self.socket = socket
        self.addr = addr
        self.payload = payload
        self.recv_size = config.get("main").get("default_recv_size", 8192)
        self.set_proto_var("ADDR", addr[0])

    def run(self):
        while True:
            log.debug(self.recv())

    def recv(self):
        load = None
        log.debug("Waiting for data")
        while not load:
            s = select.select([self.socket], [], [], 10)
            if s[0]:
                load = self.socket.recv(self.recv_size)
        return load

    def send(self, buffer):
        self.socket.send(buffer)

    def get_proto_command(self, command, default=None):
        return self.proto_commands.get(command, default)

    def set_proto_command(self, command, value):
        self.proto_commands[command] = value

    def set_proto_var(self, key, value):
        self.proto_vars[key] = value

    def get_proto_var(self, key):
        return self.proto_vars.get(key)

    @classmethod
    def guess_protocol_from_payload(cls, payload, config, addr):
        """
        Iterates through known protocols to see if the payload is recognized

        :param payload: raw payload received from a connection 
        :return: Protocol object
        """
        identified_protocol = cls
        for protocol in cls.get_known_protocols(config):
            log.debug("Checking for {}".format(protocol))
            protocol_class = core.find_protocol_class(protocol)
            new_protocol = protocol_class.guess_protocol_from_payload(payload, config, addr)
            if new_protocol != identified_protocol:
                identified_protocol = new_protocol
                break
        return identified_protocol

    @classmethod
    def get_known_protocols(cls, config):
        return config.get(cls.name).get("protocols", [])

    @classmethod
    def get_name(cls):
        return cls.name