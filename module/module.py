#!/usr/bin/python

# -*- coding: utf-8 -*-

# Copyright (C) 2009-2012:
#    Gabes Jean, naparuba@gmail.com
#    Gerhard Lausser, Gerhard.Lausser@consol.de
#    Gregory Starck, g.starck@gmail.com
#    Hartmut Goebel, h.goebel@goebel-consult.de
#
# This file is part of Shinken.
#
# Shinken is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Shinken is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with Shinken.  If not, see <http://www.gnu.org/licenses/>.


# This Class is an NSCA Arbiter module
# Here for the configuration phase AND running one

import time
import select
import socket
import struct
import random

from shinken.basemodule import BaseModule
from shinken.external_command import ExternalCommand
from shinken.log import logger

properties = {
    'daemons': ['arbiter', 'receiver'],
    'type': 'nsca_server',
    'external': True,
    'phases': ['running'],
    }


def decrypt_xor(data, key):
    keylen = len(key)
    crypted = [chr(ord(data[i]) ^ ord(key[i % keylen]))
            for i in xrange(len(data))]
    return ''.join(crypted)


def get_instance(plugin):
    """ Return a module instance for the plugin manager """
    logger.info("Get a NSCA arbiter module for plugin %s" % plugin.get_name())

    if hasattr(plugin, 'host'):
        if plugin.host == '*':
            host = ''
        else:
            host = plugin.host
    else:
        host = '127.0.0.1'

    if hasattr(plugin, 'port'):
        port = int(plugin.port)
    else:
        port = 5667

    if hasattr(plugin, 'buffer_length'):
        buffer_length = int(plugin.buffer_length)
    else:
        buffer_length = 4096

    if hasattr(plugin, 'payload_length'):
        payload_length = int(plugin.payload_length)
    else:
        payload_length = -1

    if hasattr(plugin, 'encryption_method'):
        encryption_method = int(plugin.encryption_method)
    else:
        encryption_method = 0

    if hasattr(plugin, 'password'):
        password = plugin.password
    else:
        password = ""

    if password == "" and encryption_method != 0:
        logger.error("[NSCA] No password specified whereas there is a encryption_method defined")
        logger.warning("[NSCA] Setting password to dummy to avoid crash!")
        password = "dummy"

    if hasattr(plugin, 'max_packet_age'):
        max_packet_age = min(plugin.max_packet_age, 900)
    else:
        max_packet_age = 30
    
    if hasattr(plugin, 'check_future_packet'):
        check_future_packet = bool(plugin.check_future_packet)
    else:
        check_future_packet = True


    instance = NSCA_arbiter(plugin, host, port,
            buffer_length, payload_length, encryption_method, password, max_packet_age, check_future_packet)
    return instance


class NSCA_arbiter(BaseModule):
    """Please Add a Docstring to describe the class here"""

    def __init__(self, modconf, host, port, buffer_length, payload_length, encryption_method, password, max_packet_age, check_future_packet):
        BaseModule.__init__(self, modconf)
        self.host = host
        self.port = port
        self.buffer_length = buffer_length
        self.payload_length = payload_length
        self.encryption_method = encryption_method
        self.password = password
        self.rng = random.Random(password)
        self.max_packet_age = max_packet_age
        self.check_future_packet = check_future_packet 
        logger.info("[NSCA] configuration: %s (%s), payload length: %s, encryption: %s, max age: %s, check future: %s" % (self.host, self.port, self.payload_length, self.encryption_method, self.max_packet_age, self.check_future_packet))

    def send_init_packet(self, sock):
        '''
        Build an init packet
         00-127: IV
         128-131: unix timestamp
        '''
        iv = ''.join([chr(self.rng.randrange(256)) for i in xrange(128)])
        init_packet = struct.pack("!128sI", iv, int(time.time()))
        sock.send(init_packet)
        return iv

    def read_check_result(self, data, iv, payload_length):
        '''
        Read the check result

        The !hhIIh64s128s512sh is the description of the packet.
        See Python doc for details. This is equivalent to the figure below

        00-01       Version
        02-03       Padding
        04-07       CRC32
        08-11       Timestamp
        12-13       Return Code
        14-77       Hostname
        78-205      Service name
        206-717     Service output (512 or 4096 bytes)
        718-719     Padding
        '''

        if self.encryption_method == 1:
            data = decrypt_xor(data, self.password)
            data = decrypt_xor(data, iv)

        # version, pad1, crc32, timestamp, rc, hostname_dirty, service_dirty, output_dirty, pad2
        # are the name of var if needed later
        unpackFormat = "!hhIIh64s128s%ssh" % payload_length
        
        (_, _, _, timestamp, rc, hostname_dirty, service_dirty, output_dirty, _) = \
            struct.unpack(unpackFormat, data)
        hostname = hostname_dirty.split("\0", 1)[0]
        service = service_dirty.split("\0", 1)[0]
        output = output_dirty.split("\0", 1)[0]
        logger.debug("[NSCA] read_check_result : host is %s (%s), output : %s" % (hostname, service, output))
        return (timestamp, rc, hostname, service, output)

    def post_command(self, timestamp, rc, hostname, service, output):
        '''
        Send a check result command to the arbiter
        '''
        if len(service) == 0:
            extcmd = "[%lu] PROCESS_HOST_CHECK_RESULT;%s;%d;%s\n" % \
                (timestamp, hostname, rc, output)
        else:
            extcmd = "[%lu] PROCESS_SERVICE_CHECK_RESULT;%s;%s;%d;%s\n" % \
                (timestamp, hostname, service, rc, output)

        logger.debug("[NSCA] command : %s" % (extcmd))
        e = ExternalCommand(extcmd)
        self.from_q.put(e)

    def process_check_result(self, databuffer, IV):
        payload_length = len(databuffer) - 208
        if self.payload_length != -1 and payload_length != self.payload_length:
            logger.info("[NSCA] Dropping packet with incorrect payload length.")
            return
            
        (timestamp, rc, hostname, service, output) = self.read_check_result(databuffer, IV, payload_length)
        current_time = time.time()
        check_result_age = current_time - timestamp
        if timestamp > current_time and self.check_future_packet:
            logger.info("[NSCA] Dropping packet with future timestamp.")
        elif check_result_age > self.max_packet_age:
            logger.info(
                "[NSCA] Dropping packet with stale timestamp - packet was %s seconds old." % \
                check_result_age)
        else:
            self.post_command(timestamp, rc, hostname, service, output)

    # When you are in "external" mode, that is the main loop of your process
    def main(self):
        self.set_proctitle(self.name)

        self.set_exit_handler()
        backlog = 5
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setblocking(0)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(backlog)
        input = [server]
        databuffer = {}
        IVs = {}

        while not self.interrupted:
            # outputready and exceptready unused
            inputready, _, _ = select.select(input, [], [], 1)
            for s in inputready:
                if s == server:
                    # handle the server socket
                    # address unused
                    client, _ = server.accept()
                    iv = self.send_init_packet(client)
                    IVs[client] = iv
                    input.append(client)
                else:
                    # handle all other sockets
                    try:
                        data = s.recv(self.buffer_length)
                    except:
                        continue
                    if len(data) == 0:
                        try:
                            # Closed socket
                            del databuffer[s]
                            del IVs[s]
                        except:
                            pass
                        s.close()
                        input.remove(s)
                        continue
                    if s in databuffer:
                        databuffer[s] += data
                    else:
                        databuffer[s] = data
                        
                    self.process_check_result(databuffer[s], IVs[s])
                    databuffer[s] = databuffer[s][len(databuffer[s]):]
                    # continue
                    
#                    logger.info("[NSCA] new len(databuffer) : %d" % (len(databuffer[s])))
#                    message_length = self.payload_length + 208
#                    while len(databuffer[s]) >= message_length:
                        # end-of-transmission or an empty line was received
#                        self.process_check_result(databuffer[s][0:message_length], IVs[s])
#                        databuffer[s] = databuffer[s][message_length:]
