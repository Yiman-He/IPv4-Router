#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time

from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here


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
                







def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
