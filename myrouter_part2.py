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
                prefixnet = IPv4Network(str(entry.prefix) + '/' + str(entry.mask))
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

        def addEntry_custom(last_req_time, num_retry, pkt, next_ip, intf_to_next):
            entry = self.Entry(last_req_time, num_retry, pkt, next_ip, intf_to_next)
            self.entryList.append(entry)

        # find the matched entry using arp_reply
        # return all the required info to send pkt
        # This function will only return 1 packet at a time
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
            # Processed next ips. This is a set that stores next ips that we already sent arp-requests to.
            # We do not sent arp requests 2 times for the same next-ip. That's why we need the set.
            procd_next_ips = {}
            for entry in self.entryList:
                if time.time() - entry.last_req_time >= 1:
                    # If we have sent the arp request for this nextip, no need to send again
                    if entry.next_ip in procd_next_ips:
                        entry.num_retry += 1
                        continue
                    # send arp request
                    for intf in interfaces:
                        # Once we found the correct interface, just send the request
                        if intf.name == entry.intf_to_next:
                            senderhwaddr = intf.ethaddr
                            senderprotoaddr = intf.ipaddr
                            targetprotoaddr = entry.next_ip
                            arp_request = create_ip_arp_request(senderhwaddr, senderprotoaddr, targetprotoaddr)
                            net.send_packet(intf.name, arp_request)
                            # To make sure every entry with the same ip has the same last_req_time
                            self.change_time_info(entry.next_ip, time.time())
                            # Add next_ip to the processed set
                            procd_next_ips.add(entry.next_ip)
                            log_debug("arp_request sent successfully.")
                            entry.num_retry += 1
                            break;

                
        # Print the table for debugging purposes
        def printTable(self):
            for entry in self.entryList:
                log_debug(entry.last_req_time + " " + entry.num_retry + " " + entry.pkt[IPv4].dst + " " + entry.next_ip + " " + entry.intf_to_next)

        # Check if the next_ip already exist in the queue
        def checkIPExist(self, next_ip):
            ip_list = [entry.next_ip for entry in self.entryList]
            if next_ip in ip_list:
                return True
            return False

        # Get the last req time and num_retry for an ip address
        # Assumed that in the queue, entries with the same ip addr already share the time and retry
        def get_time_retry_info(self, next_ip):
            for entry in self.entryList:
                if entry.next_ip == next_ip:
                    return entry.last_req_time, entry.num_retry
            return None, None

        def change_time_info(self, next_ip, newtime):
            for entry in self.entryList:
                if entry.next_ip == next_ip:
                    entry.last_req_time = newtime


    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        my_interfaces = self.net.interfaces()
        myips = [intf.ipaddr for intf in my_interfaces]
        # constructing forwarding table
        fwd_table = self.FwdTable()
        fwd_table.readFromFile("forwarding_table.txt")
        fwd_table.readFromRouter(my_interfaces)
        pkt_queue = self.PktQueue()
        # Initialize an empty arp_table, IP -> MAC
        arp_table = {}
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
            # Go through the queue before checking incoming packets
            pkt_queue.navigate(self.net)
            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                # Determine whether it is an ARP request
                arp = pkt.get_header(Arp)
                # The packet is not ARP request nor reply, ignore it
                if arp is None:
                    ipv4 = pkt.get_header(IPv4)
                    if ipv4 is None:
                        continue
                    # When IPv4 header is not none, this is an IPv4 packet
                    pkt_dst_ip = pkt[IPv4].dst
                    # Check if the packet is intended for the router itself
                    # If it is, just ignore and continue
                    if pkt_dst_ip in myips:
                        continue
                    # The info_list contains next_ip and interface name
                    fwd_info_list = fwd_table.findMatch(pkt_dst_ip)
                    # If there is no match in the forwarding table, drop and continue
                    if fwd_info_list is None:
                        continue
                    next_ip = fwd_info_list[0]
                    out_port = fwd_info_list[1]

                    # When then next_hop_ip is none, we just use the destination ip
                    if next_ip is None:
                        next_ip = pkt_dst_ip

                    next_mac = arp_table.get(next_ip)
                    if next_mac is not None:
                        # decrement the ttl
                        pkt[IPv4].ttl -= 1
                        pkt[Ethernet].dst = next_mac
                        # Find the source MAC address
                        # TODO Might need sanity check
                        for intf in my_interfaces:
                            if intf.name == out_port:
                                pkt[Ethernet].src = intf.ethaddr
                                break
                        # Everything goes well, just send packet
                        self.net.send_packet(out_port, pkt)
                        continue
                    else:
                        # There is no match in the arp table
                        # check if ip is already in queue
                        if not checkIPExist(next_ip):
                            # Might need sanity check
                            senderhwaddr = None
                            senderprotoaddr = None
                            for intf in my_interfaces:
                                if intf.name == out_port:
                                    senderhwaddr = intf.ethaddr
                                    senderprotoaddr = intf.ipaddr
                                    break
                            targetprotoaddr = next_ip
                            arp_request = create_ip_arp_request(senderhwaddr, senderprotoaddr, targetprotoaddr)
                            net.send_packet(out_port, arp_request)
                            pkt_queue.addEntry(pkt, next_ip, out_port)
                        else:
                            # When the ip is already in queue, get the time and the num_retry
                            # then add the pkt to the queue
                            last_req_time, num_entry = pkt_queue.get_time_retry_info(next_ip)
                            pkt_queue.addEntry_custom(last_req_time, num_retry, pkt, next_ip, intf_to_next)

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
                        # Update arp table
                        arp_table[arp.senderprotoaddr] = arp.senderhwaddr
                        # Send all the packets with the given IP address
                        while pkt_queue.checkIPExist(arp.senderprotoaddr):
                            # One packet at a time
                            pkt_info_list = pkt_queue.findMatch(arp)
                            # entry.pkt, entry.next_ip, entry.intf_to_next
                            pkt = pkt_info_list[0]
                            next_ip = pkt_info_list[1]
                            out_port = pkt_info_list[2]
                            # next_mac won't be None, not sure if sanity check is needed
                            next_mac = arp.senderhwaddr
                            # decrement the ttl
                            pkt[IPv4].ttl -= 1
                            pkt[Ethernet].dst = next_mac
                            # Find the source MAC address
                            # TODO Might need sanity check
                            for intf in my_interfaces:
                                if intf.name == out_port:
                                    pkt[Ethernet].src = intf.ethaddr
                                    break
                            # Everything goes well, just send packet
                            self.net.send_packet(out_port, pkt)









def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
