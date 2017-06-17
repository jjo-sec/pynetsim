# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.

import dpkt.dns
import dpkt.dpkt

import pynetsim.protocols.udp as udp


class NTP(udp.UDP):

    name = "ntp"

    @classmethod
    def guess_protocol_from_payload(cls, payload, config, addr):
        protocol = udp.UDP
        try:
            ntp = dpkt.ntp.NTP(payload)
            if len(ntp.data) == 0:
                protocol = cls
        except dpkt.dpkt.NeedData:
            pass
        return protocol
