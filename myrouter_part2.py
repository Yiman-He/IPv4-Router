#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time

from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *
from switchyard.lib.address import *

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here

    class FwdTable:
        def __init__(self):
        self.entryList = []

        class Entry:
            def __init__(self, prefix, mask, next_hop_ip, intf_to_next):
                self.prefix = prefix
                self.mask = mask
                self.next_hop_ip = next_hop_ip
                self.intf_to_next = intf_to_next # This is the name of the port

        def addEntry(self, prefix, mask, next_hop_ip, intf_to_next):
            entry = self.Entry(prefix, mask, next_hop_ip, intf_to_next)
            self.entryList.append(entry)

        # This will return a list containing the next hop ip and 
        # the name of the interface
        # destaddr is destination IP address
        def findMatch(self, destaddr):
            matchedEntry = None
            maxPrefixLen = 0 # The length of the longest prefix
            for entry in self.entryList:
                prefixnet = IPv4Network(entry.prefix + '/' + entry.mask)
                if destaddr in prefixnet:
                    # When the prefix length is larger than the previous match, 
                    # update the matched entry
                    if prefixnet.prefixlen > maxPrefixLen:
                        matchedEntry = entry
                        maxPrefixLen = prefixnet.prefixlen
            # Now we found the entry, we should return the next hop ip and interface name
            if matchedEntry is None:
                return None
            return [entry.next_hop_ip, entry.intf_to_next]

        # Print the table for debugging purposes
        def printTable(self):
            for entry in self.entryList:
                if entry.next_hop_ip is None:
                    log_debug(entry.prefix + " " + entry.mask + " " + "None" + " " + entry.intf_to_next)
                    continue
                log_debug(entry.prefix + " " + entry.mask + " " + entry.next_hop_ip + " " + entry.intf_to_next)

        # Construct the table using a file
        def readFromFile(self, fileName):
            file = open(fileName, "r")
            lines = file.readlines()
            for line in lines:
                wordList = line.split()
                # sanity check
                if len(wordList) != 4:
                    log_debug("problem in input file")
                    return
                self.addEntry(wordList[0], wordList[1], wordList[2], wordList[3])


        def readFromRouter(self, interfaces):
            # interfaces should be self.net.interfaces()
            for intf in interfaces:
                self.addEntry(intf.ipaddr, intf.netmask, None, intf.name)

    class PktQueue:

        def __init__(self):
            self.entryList = []

        class Entry:
            def __init__(self, last_req_time, num_retry, pkt, next_ip, intf_to_next):
                self.last_req_time = last_req_time
                self.num_retry = num_retry
                self.pkt = pkt
                self.next_ip = next_ip # This could etiher be the next hop ip or just dst ip
                self.intf_to_next = intf_to_next

        def addEntry(self, pkt, next_ip, intf_to_next):
            last_req_time = time.time()
            num_retry = 1
            entry = self.Entry(last_req_time, num_retry, pkt, next_ip, intf_to_next)
            self.entryList.append(entry)

        # find the matched entry using arp_reply
        # return all the required info to send pkt
        def findMatch(self, arp_reply):
            for i in range(len(self.entryList)):
                # Destination IP of packet matches the sender IP from ARP reply
                entry = self.entryList[i]
                if entry.next_ip == arp_reply.senderprotoaddr:
                    entry = self.entryList.pop(i)
                    return [entry.pkt, entry.next_ip, entry.intf_to_next]
            return None

        # Iterate through the queue 
        # send requests or delete entry
        def navigate(self, net):
            interfaces = net.interfaces()
            # remove entries with retries == 3
            self.entryList[:] = [entry for entry in self.entryList if entry.num_retry < 3]
            for entry in self.entryList:
                if time.time() - entry.last_req_time >= 1:
                    # send arp request
                    for intf in interfaces:
                        # Once we found the correct interface, just send the request
                        if intf.name == entry.intf_to_next:
                            senderhwaddr = intf.ethaddr
                            senderprotoaddr = intf.ipaddr
                            targetprotoaddr = entry.next_ip
                            arp_request = create_ip_arp_request(senderhwaddr, senderprotoaddr, targetprotoaddr)
                            net.send_packet(intf.name, arp_request)
                            log_debug("arp_request sent successfully.")
                            entry.num_retry += 1
                            break;

                
        # Print the table for debugging purposes
        def printTable(self):
            for entry in self.entryList:
                log_debug(entry.last_req_time + " " + entry.num_retry + " " + entry.pkt.dstip + " " + entry.next_ip + " " + entry.intf_to_next)

    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        my_interfaces = self.net.interfaces()
        myips = [intf.ipaddr for intf in my_interfaces]
        while True:
            gotpkt = True
            try:
                timestamp,input_port,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                # Initialize an empty arp_table, IP -> MAC
                arp_table = {}
                # Determine whether it is an ARP request
                arp = pkt.get_header(Arp)
                # The packet is not ARP request nor reply, ignore it
                if arp is None:
                    continue;
                # Determine it is ARP request or ARP reply
                # For an ARP request, the targethwaddr field is not filled
                # May need to use "ff:ff:ff:ff:ff:ff" instead

                # This is when an ARP request is received
                if arp.targethwaddr == SpecialEthAddr.ETHER_BROADCAST.value:
                    # determine whether the targetprotoaddr field is assigned to one of the ports
                    if arp.targetprotoaddr in myips:
                        # Create and send ARP reply
                        senderhwaddr = "ff:ff:ff:ff:ff:ff"
                        for intf in my_interfaces:
                            if input_port == intf.name:
                                senderhwaddr = intf.ethaddr
                                break
                        targethwaddr = arp.senderhwaddr
                        senderprotoaddr = arp.targetprotoaddr
                        targetprotoaddr = arp.senderprotoaddr
                        arp_reply = create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr)
                        self.net.send_packet(input_port, arp_reply)

                # This is when an ARP reply is received
                else:
                    if arp.targetprotoaddr in myips:
                        arp_table[arp.senderprotoaddr] = arp.senderhwaddr








def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
