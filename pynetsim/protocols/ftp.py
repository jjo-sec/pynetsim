# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.

import select
import time
import logging

from pynetsim.protocols.tcp import TCP

log = logging.getLogger(__name__)


class FTP(TCP):

    name = "ftp"

    proto_commands = dict(USER="331 Password required for {USER}\r\n",
                          PASS="230 User {USER} logged in.\r\n",
                          SYST="215 UNIX Type: L8\r\n",
                          CWD="""250 CWD command successful. "{CWD}" is current directory.\r\n""",
                          PWD="""257 "{CWD}" is current directory.\r\n""",
                          TYPE="200 Type set to {TYPE}.\r\n",
                          SIZE="213 {RANDOM_SIZE}\r\n",
                          PASV="500 PASV command not supported.\r\n",
                          LIST="",
                          FEAT="211-Extensions Supported:\r\nSIZE\r\nCLNT\r\n211 End.\r\n",
                          CLNT="""200 "{CLNT}" noted.""",
                          RETR="{RANDOM_DATA}",
                          MKD="""257 "{MKD}": The directory was successfully created.\r\n""",
                          PORT="",
                          STOR="",

                          )

    proto_vars = dict(CWD="/",
                      RANDOM_SIZE=123453,
                      RANDOM_DATA="a"*123453)

    def run(self):
        load = self.payload
        while load:
            try:
                if load:
                    response = self.get_response(load)
                    if response:
                        self.send(response)

                load = self.recv()
                log.debug(load)
            except Exception as e:
                log.exception(e)
                break
        # attempt to temp hang the client to keep them from exiting prematurely
        time.sleep(30)
        self.socket.close()

    def get_response(self, payload):
        response = None
        command_parts = payload.decode("utf-8").strip().split(" ")
        command = command_parts[0]
        if len(command_parts) == 2:
            command_val = command_parts[1]
            self.set_proto_var(command, command_val)

        for req, res in self.proto_commands.items():
            if command == req:
                response = self.get_proto_command(command)
                if response:
                    response = bytes(response.format(**self.proto_vars), encoding="ascii")
                break
        return response

    def recv(self):
        data = None
        s = select.select([self.socket], [], [], 10)
        if s[0]:
            data = self.socket.recv(self.recv_size)
        return data

    def send(self, buffer):
        self.socket.send(buffer)

    def handle_port_command(self):
        pass

    def handle_pasv_command(self):
        raise RuntimeError("Currently Not Implemented")

    @classmethod
    def guess_protocol_from_payload(cls, payload, config, addr):
        """
        Iterates through known protocols to see if the payload is recognized

        :param payload: raw payload received from a connection 
        :param config: configuration object
        :param addr: address of client
        :return: Protocol object
        """
        identified_protocol = TCP
        if payload.startswith((b"USER ",)):
            identified_protocol = FTP
        return identified_protocol
