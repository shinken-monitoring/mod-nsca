#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2009-2012:
#    Gabes Jean, naparuba@gmail.com
#    Gerhard Lausser, Gerhard.Lausser@consol.de
#    Gregory Starck, g.starck@gmail.com
#    Hartmut Goebel, h.goebel@goebel-consult.de
#    Frédéric Mohier, frederic.mohier@gmail.com
#    David Durieux, d.durieux@siprossii.com
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

import binascii

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

    host = getattr(plugin, 'host', '127.0.0.1')
    if host == '*':
        host = ''
    
    port = int(getattr(plugin, 'port', '5667'))
    buffer_length = int(getattr(plugin, 'buffer_length', '4096'))
    payload_length = int(getattr(plugin, 'payload_length', '-1'))
    encryption_method = int(getattr(plugin, 'encryption_method', '0'))

    backlog = int(getattr(plugin, 'backlog', '10'))

    password = getattr(plugin, 'password', '')
    if password == "" and encryption_method != 0:
        logger.error("[NSCA] No password specified whereas there is a encryption_method defined")
        logger.warning("[NSCA] Setting password to dummy to avoid crash!")
        password = "dummy"

    max_packet_age = min(int(getattr(plugin, 'max_packet_age', '30')), 900)
    check_future_packet = bool(getattr(plugin, 'check_future_packet', 0))

    instance = NSCA_arbiter(plugin, host, port,
            buffer_length, payload_length, encryption_method, password, max_packet_age, check_future_packet,
            backlog)
    return instance


class NSCA_arbiter(BaseModule):
    """Please Add a Docstring to describe the class here"""

    def __init__(self, modconf, host, port, buffer_length, payload_length, encryption_method, password, max_packet_age, check_future_packet, backlog):
        BaseModule.__init__(self, modconf)
        self.host = host
        self.port = port
        self.backlog = backlog
        self.buffer_length = buffer_length
        self.payload_length = payload_length
        self.encryption_method = encryption_method
        self.password = password
        self.rng = random.Random(password)
        self.max_packet_age = max_packet_age
        self.check_future_packet = check_future_packet 
        logger.info("[NSCA] configuration, allowed hosts : '%s'(%s), buffer length: %s, payload length: %s, encryption: %s, max packet age: %s, check future packet: %s, backlog: %d", self.host, self.port, self.buffer_length, self.payload_length, self.encryption_method, self.max_packet_age, self.check_future_packet, self.backlog)

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
        206-717     Plugin output (512 or 4096 bytes)
        718-719     Padding

        nsca.c (last version as of 2014-07)
        #define MAX_HOSTNAME_LENGTH         64
        #define MAX_DESCRIPTION_LENGTH      128
        #define MAX_PLUGINOUTPUT_LENGTH     4096

        #define OLD_PLUGINOUTPUT_LENGTH     512
        #define OLD_PACKET_LENGTH (( sizeof( data_packet) - ( MAX_PLUGINOUTPUT_LENGTH - OLD_PLUGINOUTPUT_LENGTH)))

        /* data packet containing service check results */
        typedef struct data_packet_struct{
            int16_t   packet_version;
            u_int32_t crc32_value;
            u_int32_t timestamp;
            int16_t   return_code;
            char      host_name[MAX_HOSTNAME_LENGTH];
            char      svc_description[MAX_DESCRIPTION_LENGTH];
            char      plugin_output[MAX_PLUGINOUTPUT_LENGTH];
        }data_packet;

        /* initialization packet containing IV and timestamp */
        typedef struct init_packet_struct{
            char      iv[TRANSMITTED_IV_SIZE];
            u_int32_t timestamp;
        }init_packet;
        '''

        if self.encryption_method == 1:
            data = decrypt_xor(data, self.password)
            data = decrypt_xor(data, iv)
            logger.debug("[NSCA] Decrypted NSCA packet: %s", binascii.hexlify(data))

        try:
            # Python pack format for NSCA C structure
            # Depending on requested payload length
            unpackFormat = "!hhIIh64s128s%ssh" % payload_length

            # version, pad1, crc32, timestamp, rc, hostname_dirty, service_dirty, output_dirty, pad2
            # are the name of unpacked structure elements
            (version, pad, crc32, timestamp, rc, hostname_dirty, service_dirty, output_dirty, _) = \
                struct.unpack(unpackFormat, data)
            hostname = hostname_dirty.split("\0", 1)[0]
            service = service_dirty.split("\0", 1)[0]
            output = output_dirty.split("\0", 1)[0]
            logger.debug("[NSCA] Decoded NSCA packet: host/service: %s/%s, timestamp: %d, output: %s", hostname, service, timestamp, output[:32])
            return (timestamp, rc, hostname, service, output)
        except Exception as e:
            logger.warning("[NSCA] Unable to decode NSCA packet: %s", str(e))
            logger.warning("[NSCA] Faulty NSCA packet content: %s", binascii.hexlify(data))
            return (0, 0, '', '', '')

    def post_command(self, timestamp, rc, hostname, service, output):
        '''
        Send a check result command to the arbiter
        '''
        if not service:
            extcmd = "[%lu] PROCESS_HOST_CHECK_RESULT;%s;%d;%s\n" % \
                (timestamp, hostname, rc, output)
        else:
            extcmd = "[%lu] PROCESS_SERVICE_CHECK_RESULT;%s;%s;%d;%s\n" % \
                (timestamp, hostname, service, rc, output)

        logger.debug("[NSCA] external command sent: %s" % (extcmd))
        e = ExternalCommand(extcmd)
        self.from_q.put(e)

    def process_check_result(self, databuffer, IV):
        # 208 is the size of fixed received data ... NSCA packets are 208+512 (720) or 208+4096 (4304)
        if not databuffer:
            logger.warning("[NSCA] Received an empty NSCA packet")
            return

        logger.debug("[NSCA] Received NSCA packet: %s", binascii.hexlify(databuffer))

        payload_length = len(databuffer) - 208
        if payload_length != 512 and payload_length != 4096:
            logger.warning("[NSCA] Received packet with unusual payload length: %d.", payload_length)
            
        if self.payload_length != -1 and payload_length != self.payload_length:
            logger.warning("[NSCA] Dropping packet with incorrect payload length.")
            return
            
        (timestamp, rc, hostname, service, output) = self.read_check_result(databuffer, IV, payload_length)
        current_time = time.time()
        check_result_age = current_time - timestamp
        if timestamp > current_time and self.check_future_packet:
            logger.warning("[NSCA] Dropping packet with future timestamp.")
        elif check_result_age > self.max_packet_age:
            logger.info(
                "[NSCA] Dropping packet with stale timestamp - packet was %s seconds old. Timestamp: %s for %s/%s" % \
                (check_result_age, timestamp, hostname, service))
        else:
            self.post_command(timestamp, rc, hostname, service, output)

    # Because the module is an "external" one, main loop of your process
    def main(self):
        self.set_proctitle(self.name)

        self.set_exit_handler()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setblocking(0)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(self.backlog)
        input = [server]
        databuffer = {}
        IVs = {}

        while not self.interrupted:
            # outputready and exceptready unused
            inputready, _, _ = select.select(input, [], [], 1)
            for s in inputready:
                if s == server:
                    # handle the server socket
                    try:
                        client, _ = server.accept()
                        iv = self.send_init_packet(client)
                        IVs[client] = iv
                        input.append(client)
                    except Exception as e:
                        logger.warning("[NSCA] Exception on socket connecting: %s", str(e))
                        continue
                else:
                    # handle all other sockets
                    try:
                        data = s.recv(self.buffer_length)
                        if s in databuffer:
                            databuffer[s] += data
                        else:
                            databuffer[s] = data
                    except Exception as e:
                        logger.warning("[NSCA] Exception on socket receiving: %s", str(e))
                        continue
                        
                    if len(data) == 0:
                        self.process_check_result(databuffer[s], IVs[s])
                        try:
                            # Closed socket
                            del databuffer[s]
                            del IVs[s]
                        except:
                            pass
                        s.close()
                        input.remove(s)
