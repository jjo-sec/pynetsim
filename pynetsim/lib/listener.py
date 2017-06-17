# Copyright (C) 2017 Jason Jones.
# This file is part of 'PyNetSim' - https://github.com/arbor-jjones/pynetsim
# See the file 'LICENSE' for copying permission.

import ssl
import socket
import select
import logging
import struct

from concurrent.futures import ThreadPoolExecutor

import pynetsim.lib.core as core
from pynetsim.protocols.tcp import TCP

log = logging.getLogger(__name__)


class SocketListener(object):

    protocol = "null"

    def __init__(self, config):
        self.config = config
        self.sock = None
        self.futures = dict()
        self.protocols = config.get(self.protocol).get("protocols", [])
        self.max_workers = config.get("main").get("max_threads", 1000)
        self.listen_port = config.get("main").get("listen_port", 12345)
        self.listen_host = config.get("main").get("listen_host", "127.0.0.1")
        self.recv_size = config.get("main").get("default_recv_size", 8192)
        self.pool = ThreadPoolExecutor(max_workers=self.max_workers)

    def shutdown(self):
        log.debug("Stopping running threads + connections")
        if self.sock:
            self.sock.close()
        for future, conn in self.futures.items():
            if future.running():
                conn.close()
                log.debug("{}: {}".format(self, future.cancel()))
        self.pool.shutdown(wait=False)

    def get_known_protocols(self):
        return self.protocols.keys()

    def conn_completed(self, future):
        """
        Perform operations after a future exits. For now that means making sure the connection is closed

        :param future: Future instance used to key into dict
        :return: None
        """
        conn = self.futures.pop(future)
        try:
            conn.close()
        except:
            pass

    def guess_protocol(self, first_payload, config, addr=None):
        proto_class = core.find_protocol_class(self.protocol)
        return proto_class.guess_protocol_from_payload(first_payload, config, addr)


class TCPSocketListener(SocketListener):

    protocol = "tcp"

    def start(self):
        """
        Spin up the TCP listener

        :return: None
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            self.sock.bind((self.listen_host, self.listen_port))
            self.sock.listen(1)
            self.sock.settimeout(10)
        except Exception as e:
            log.exception(e)
            self.shutdown()
            return
        log.debug("Started TCP Socket Listener")
        while True:
            try:
                conn, addr = self.sock.accept()
                dst = conn.getsockopt(socket.SOL_IP, 80, 16)
                srv_port, srv_ip = struct.unpack("!2xH4s8x", dst)
                srv_ip = socket.inet_ntoa(srv_ip)
                log.debug("New connection from {}:{} => {}:{}".format(addr[0], addr[1], srv_ip, srv_port))
                future = self.pool.submit(self.handle_connection, conn, addr)
                self.futures[future] = conn
                future.add_done_callback(self.conn_completed)
            except socket.timeout:
                pass

    def handle_connection(self, conn, addr):
        """
        Creates a new connection handler thread using the specified protocol

        :param conn: Incoming connection
        :param addr: Source address
        :return: None
        """
        try:
            s = select.select([conn], [], [], 2)
            if s[0]:
                first_payload = conn.recv(self.recv_size, socket.MSG_PEEK)
                if core.is_tls_hello(first_payload):
                    log.debug("SSL connection received")
                    conn = ssl.wrap_socket(conn,
                                           ssl_version=ssl.PROTOCOL_SSLv23,
                                           certfile="/tmp/cert.pem",
                                           keyfile="/tmp/key.pem",
                                           server_side=True,
                                           do_handshake_on_connect=True)
                    s = select.select([conn], [], [], 1)
                    if s[0]:
                        first_payload = conn.recv(self.recv_size)
                    else:
                        first_payload = None
                else:
                    first_payload = conn.recv(self.recv_size)
            else:
                first_payload = None
            if first_payload:
                protocol_class = self.guess_protocol(first_payload, self.config)
            else:
                conn.send(bytes("{}\r\n".format(self.config.get("main").get("probe_response", "220 YOLO")), encoding="utf-8"))
                s = select.select([conn], [], [], 5)
                if s[0]:
                    first_payload = conn.recv(self.recv_size)
                    protocol_class = self.guess_protocol(first_payload, self.config)
                else:
                    protocol_class = TCP
            protocol = protocol_class(self.config, conn, addr, payload=first_payload)
            log.debug("Connection from {}:{} detected as {}".format(addr[0], addr[1], protocol.get_name()))
            protocol.run()
        except Exception as e:
            log.exception(e)


class UDPSocketListener(SocketListener):

    protocol = "udp"
    
    def start(self):
        log.debug("Starting UDP socket listener")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.bind((self.listen_host, self.listen_port))
        sock.settimeout(10)
        while True:
            try:
                payload, addr = sock.recvfrom(self.recv_size)
                log.debug("New UDP connection from {}:{}".format(*addr))
                self.pool.submit(self.handle_connection, payload, sock, addr)
            except socket.timeout:
                pass

    def handle_connection(self, payload, sock, addr):
        """
        Creates a new connection handler thread using the specified protocol

        :param payload: First payload
        :param sock: Incoming connection
        :param addr: Source address
        :return: None
        """
        try:
            protocol_class = self.guess_protocol(payload, self.config, addr=addr)
            protocol = protocol_class(self.config, sock, addr, payload=payload)
            log.debug("Connection from {}:{} detected as {}".format(addr[0], addr[1], protocol.get_name()))
            protocol.run()
        except Exception as e:
            log.exception(e)
