# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.

import time
import logging
import ssl

from pynetsim.protocols.tcp import TCP

log = logging.getLogger(__name__)


class SMTP(TCP):

    name = "smtp"

    proto_commands = dict(EHLO=("250-{HOSTNAME} Hello {EHLO} [{ADDR}]\r\n250-SIZE 52428800\r\n250-PIPELINING\r\n250-STARTTLS\r\n250-AUTH LOGIN\r\n250 HELP\r\n",),
                          HELO=("250-{HOSTNAME} Hello {HELO} [{ADDR}]\r\n250-SIZE 52428800\r\n250-PIPELINING\r\n250-STARTTLS\r\n250-AUTH LOGIN\r\n250 HELP\r\n",),
                          #AUTH_PLAIN=("334 VXNlcm5hbWU6\r\n", "334 UGFzc3dvcmQ6\r\n", "235 Authentication succeeded\r\n"),
                          MAIL=("250 OK\r\n",),
                          RCPT=("250 ACCEPTED\r\n",),
                          DATA=("""354 Enter message, ending with "." on a line by itself\r\n""",),
                          QUIT=("221 {HOSTNAME} closing connection",),
                          RSET=("250 2.0.0 OK\r\n",))

    proto_vars = dict(HOSTNAME="mx.google.com")

    def run(self):
        # . used to end a mail message
        self.set_proto_command(".", ("250 OK id=1Mugho-0003Dg-Un\r\n",))
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
        payload = payload.strip().split(b"\r\n")[-1]
        if payload.upper().startswith(b"AUTH"):
            responses = self.handle_auth(payload)
        elif payload.upper().startswith(b"STARTTLS"):
            log.debug("Wrapping socket in SSL due to STARTTLS")
            self.send(b"220 Go ahead\r\n")
            self.socket = ssl.wrap_socket(self.socket,
                                          ssl_version=ssl.PROTOCOL_SSLv23,
                                          certfile="/tmp/cert.pem",
                                          keyfile="/tmp/key.pem",
                                          server_side=True)
            self.socket.do_handshake()
            responses = []
        else:
            responses = []
            command_parts = payload.decode("utf-8").strip().split(" ")
            command = command_parts[0]
            if len(command_parts) == 2:
                command_val = command_parts[1]
                self.set_proto_var(command.upper(), command_val)
            command_us = payload.decode("utf-8").strip().replace(" ", "_")
            log.debug(command)
            log.debug(command_us)
            for req, res in self.proto_commands.items():
                if command.upper() == req:
                    for response in self.get_proto_command(command.upper(), []):
                        log.debug(response)
                        responses.append(bytes(response.format(**self.proto_vars), encoding="ascii"))
                    break
                elif command_us.upper() == req:
                    for response in self.get_proto_command(command_us.upper(), []):
                        responses.append(bytes(response.format(**self.proto_vars), encoding="ascii"))
                    break
        return responses

    def recv(self):
        load = self.socket.recv(self.recv_size)
        return load

    def send(self, buffer):
        self.socket.send(buffer)

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
        if payload.lower().startswith((b"helo", b"ehlo")):
            identified_protocol = SMTP
        return identified_protocol

    def handle_auth(self, payload):
        """
        Handle various SMTP authentication measures

        :param payload: Packet payload
        :return: List of responses
        """
        responses = []
        payload_parts = payload.split(b" ")
        if b"PLAIN" in payload.upper():
            responses = [b"235 Authentication succeeded\r\n"]
        elif b"LOGIN" in payload.upper():
            if len(payload_parts) == 2:
                responses = [b"334 VXNlcm5hbWU6\r\n", b"334 UGFzc3dvcmQ6\r\n", b"235 Authentication succeeded\r\n"]
            elif len(payload_parts) == 3:
                responses = [b"334 UGFzc3dvcmQ6\r\n", b"235 Authentication succeeded\r\n"]
        return responses