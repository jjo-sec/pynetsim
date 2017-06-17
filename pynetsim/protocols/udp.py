# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.

import logging

from pynetsim.protocols.protocol import BotWhisperer

log = logging.getLogger(__name__)


class UDP(BotWhisperer):

    name = "udp"

    def run(self):
        """
        For now send no response from the default UDP handler

        :return: None
        """
        return

    def send(self, data_buffer):
        log.debug("Sending {}".format(data_buffer))
        self.socket.sendto(data_buffer, self.addr)
