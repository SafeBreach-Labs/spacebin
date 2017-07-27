#!/usr/bin/env python
# Copyright (c) 2016, SafeBreach
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import socket
import select
import sys
import collections


####################
# Global Variables #
####################

__version__ = "1.0"
__author__ = "Itzik Kotler"
__copyright__ = "Copyright 2016, SafeBreach"


#############
# Functions #
#############

def _udp_server_or_none(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', port))
    except Exception as e:
        print "%d/udp: %s" % (port, str(e))
        return None
    return s


def _tcp_server_or_none(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', port))
        s.listen(socket.SOMAXCONN)
    except Exception as e:
        print "%d/tcp: %s" % (port, str(e))
        return None
    return s


def _close_socket_and_queue(sock, inputs, outputs, queue):

    try:
        inputs.remove(sock)
    except ValueError:
        pass

    try:
        outputs.remove(sock)
    except ValueError:
        pass

    sock.close()

    sock_queue = queue.pop(sock, None)
    if sock_queue:
        sock_queue.clear()


def _analyze(data, port, on_connect):
    return data


def serve_forever(servers):
    inputs = list(servers)
    outputs = []
    data_ready = {}

    while True:

        readable, writable, error = select.select(inputs, outputs, inputs, 0.1)

        # Readable
        for s in readable:

            if s in servers and s.type == socket.SOCK_STREAM:
                client_socket, client_address = s.accept()
                print "New connection from %s on %d/%s" % (client_address, s.getsockname()[1], "tcp" if s.type == socket.SOCK_STREAM else "udp")
                inputs.append(client_socket)

            # New Data!
            else:

                src_addr = None
                on_connect = False

                # TCP or UDP?
                if s.type == socket.SOCK_STREAM:
                    data = s.recv(256)
                    src_addr = s.getpeername()

                else:
                    (data, src_addr) = s.recvfrom(256)

                # Read Data
                if data:
                    print "< [%s on %d/%s]: %s" % (src_addr, s.getsockname()[1], "tcp" if s.type == socket.SOCK_STREAM else "udp", data)

                    # 1st Time?
                    if s not in data_ready:
                        data_ready[s] = collections.deque()
                        on_connect = True

                    data_ready[s].append((data, src_addr, on_connect))

                    if s not in outputs:
                        outputs.append(s)

                # No Data means Close TCP Connection
                elif not data and s.type == socket.SOCK_STREAM:
                    print "Closing connection %s to %d/%s" % (str(s.getpeername()), s.getsockname()[1], "tcp" if s.type == socket.SOCK_STREAM else "udp")

                    _close_socket_and_queue(s, inputs, outputs, data_ready)

                    if s in writable:
                        writable.remove(s)

        # Writeable
        for s in writable:

            try:
                (data, peer, on_connect) = data_ready[s].popleft()
                reply = _analyze(data, s.getsockname()[1], on_connect)

            except IndexError:
                outputs.remove(s)

            else:
                if s.type == socket.SOCK_STREAM:
                    s.send(reply)
                if s.type == socket.SOCK_DGRAM:
                    s.sendto(reply, src_addr)

                print "> [%s on %d/%s]: %s" % (peer, s.getsockname()[1], "tcp" if s.type == socket.SOCK_STREAM else "udp", reply)

        #  Error
        for s in error:
            _close_socket_and_queue(s, inputs, outputs, data_ready)


def main(argv):
    servers = []

    if len(argv) < 2:
        print "usage: %s [ <START PORT>-<END PORT>,<PORT #1>,<PORT 2>, ... ]" % (argv[0])
        return 0

    # i.e. 80,443,6667-7000
    for port_or_ports_range in argv[1].split(','):
        ports = []

        if '-' in port_or_ports_range:
            # i.e. 80-443
            min_port, max_port = port_or_ports_range.split('-')
            ports = xrange(int(min_port), int(max_port))
        else:
            # i.e. 80
            ports = [int(port_or_ports_range)]

        for port in ports:
            for srv_socket in [_tcp_server_or_none(port), _udp_server_or_none(port)]:
                if srv_socket is not None:
                    print "Binding port %d/%s ..." % (port, "tcp" if srv_socket.type == socket.SOCK_STREAM else "udp")
                    servers.append(srv_socket)

    serve_forever(servers)


###############
# Entry Point #
###############

if __name__ == "__main__":
    sys.exit(main(sys.argv))
