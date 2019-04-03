# IPv4 Router

## Overview
Some basic functions of an IPv4 Router will be implemented in this project.

* [ ] Responding to/making ARP requests

* [ ] Maintaining a route lookup table

* [ ] Receiving packets and forwarding them directly to their destination using the route lookup table

* [ ] Learning routes dynamically

* [ ] Use mininet and see packets in a live network

## Part1 Address Resolution Protocol(ARP)

ARP is a protocol used for resolving IP addresses to MAC addresses. Hosts in the network need to keep a mapping between IP and link-layer addresses and they can use ARP to broadcast query messages for a particular IP address in their physical networks so that the appropriate host can reply this query with its link-layer address.

The main task for this exercise is to modify the Router class to do the following:

1. Initialize an empty *arp_table* for storing ARP entries which is mapping of IP addresses to MAC addresses.
2. Upon receiving a packet, determine whether it is an ARP request.
    * For ARP packet headers, there are 4 addresses in total. They are:
        1. Source Ethernet Address, called *senderhwaddr*.
        1. Source IP Address, called *senderprotoaddr*.
        1. Destination Ethernet Address, called *targethwaddr*. (**Not filled in**)
        1. Destination IP Address, called *targetprotoaddr*.
    * The packet header class for ARP is named *Arp*.
    * To obtain the the ARP header from an incoming packet (if it exists), you can do something like:
    ```python
    arp = packet.get_header(Arp)
    ```
    * See the Arp packet header [reference](https://jsommers.github.io/switchyard/reference.html?highlight=arp#switchyard.lib.packet.Arp) in the Switchyard documentation for more.
3. For each ARP request, you should determine whether the *targetprotoaddr* field (IP address destination) in the ARP header is an IP address assigned to one of the interfaces on your router. 
    * If the destination IP address is one that is assigned to an interface of your Router, create and send an appropriate ARP reply. The ARP reply should be sent out of the same interface on which the ARP request arrived. (If the destination IP address is not assigned to one of the router's interfaces, drop the packet.)
4. If you receive an ARP reply, determine whether the *targetprotoaddr* field (IP address destination) in the ARP header is an IP address assigned to one of the interfaces on your router.
    * If the destination IP address is one that is assigned to an interface of your Router, you should store a mapping of the ARP in your router. i.e, Add the *senderprotoaddr* to *senderhwaddr* mapping into your *arp_table*.
5. If a packet that you receive in the router is not an ARP request, you should ignore it (drop it) for now. (**I would assume that ARP reply will not be dropped immediately**)

2 Helper functions(defined in *switchyard.lib.packet.util* could be used.

```python
create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr)
create_ip_arp_request(senderhwaddr, senderprotoaddr, targetprotoaddr)
```

These two functions above return a full Packet object including Ethernet and Arp headers, all filled in. So you can simply call the functions with the appropriate fields.


## Part2 IP Forwarding

 The fundamental thing that routers do: 
 1. receive packets 
 1. match their destination addresses against a forwarding table
 1. forward them out the correct interface.

 A **forwarding table** is needed to be implemented. Each entry contains:
 1. A network *prefix* (e.g., 149.43.0.0)
 1. A network *mask* (e.g., 255.255.0.0)
 1. The "next hop" IP address, if the destination network prefix is not for a directly attached network
 1. The network interface name through which packets destined to the given network should be forwarded. 

The forwarding table is build from 2 sources.
 1. The list of router interfaces from:
 ```python
 net.interfaces()
 ```
 2. Reading from file named **forwarding_table.txt**. The file can be assumed to exist in the same directory where your router is starting up.

A typical forwarding table may look like this:
```
172.16.0.0 255.255.0.0 192.168.1.2 router-eth0
192.168.200.0 255.255.255.0 192.168.200.1 router-eth1
```

However, from the first source, we construct entries in the forwarding table without the field of "next hop". In this case, the entry will be like this:
```
172.16.0.0 255.255.0.0 None router-eth0
```
The prefix(ip), the mask and the interface name are accessible through the interface.

```python
intf.ipaddr
intf.netmask
intf.name
```
After building the forwarding table, destination address will be matched against the forwarding table. In case of two items in the table matching, the **longest prefix match** should be used.

To find out the length of a subnet prefix, use the following code pattern:
```python
from switchyard.lib.address import *
netaddr = IPv4Network('172.16.0.0/255.255.255.0')
netaddr.prefixlen # -> 24
```

To check whether a given address matches a prefix, we do this:

```python
prefixnet = IPv4Network('172.16.0.0/16')
# same as IPv4Network('172.16.0.0/255.255.0.0')
matches = destaddr in prefixnet
# matches -> True
```

Once the forwarding table lookup is complete, next steps are:

1. Accept Arp packets and IPv4 packets and drop everything else. IPv4 headers must be present.
2. Decrement the *TTL* field in the IP header by 1 (This could be done before the lookup). For this project, *TTL* value is greater than 0 after decrementing.
3. Create a new Ethernet header for the IP packet to be forwarded. There are 3 fields in the Ethernet header. *dst*, *ethertype* and *src*. *src* is the source mac address. 
```python
src = intf.ethaddr
``` 
4. *dst* is the ethernet MAC address of the **next hop** (or just the **destination host**). To get the *dst*,
 * If the ARP address is already stored in the ARP table, use that to send the packet. Update the time of use of this ARP entry in the ARP table.
 * Otherwise, send an Arp request to obtain the next hop MAC address.
5. For handling ARP queries so the following:
 * Send an ARP request for the IP address needing to be "resolved".
 * When an ARP reply is received, 
    1. store the information in your table, 
    2. complete the Ethernet header for the IP packet to be forwarded, 
    3. and send it along. 
    4. ~~Also create a cache of IP addresses and the Ethernet MAC addresses that they correspond to.~~ (**This is not needed**)
 * If no ARP reply is received within 1 second in response to an ARP request, send another ARP request. 
 * Send up to (exactly) 3 ARP requests for a given IP address. If no ARP reply is received after 3 requests, give up and drop the packet (and do nothing else).

**Recommended:** 
* Create a queue that contains information about IP packets awaiting ARP resolution.
* Each time through the main while loop, process the items in the queue to see whether an ARP request retransmission needs to be sent.
* If you receive an ARP reply packet 
    1. remove an item from the queue, 
    2. update the ARP table, 
    3. construct the Ethernet header, 
    4. and send the packet.
* A separate class may be needed to represent packets in the queue waiting for ARP responses. 
* The class contains variables to:
    1. The most recent time an ARP request was sent
    2. the number of retries
    3. Other information (packet information)

Use the built-in time module:

```python
time.time() # -> current time in seconds as a float.
```

Two special cases to consider:
1. If there is no match in the forwarding table, just drop the packet.
2. If packet is for the router itself (i.e., destination address is an address of one of the router's interfaces), also drop/ignore the packet. i.e,

```python
packet.dstip == interface.ipaddr
```


## Part 3: Route information learning

Route information within a network are dynamically learnt using intra-domain routing protocols like OSPF and RIP. These are complex protocol and hence we will implement our own learning mechanism.

The dynamic routing packet consists of:
1. router prefix, 
2. mask, 
3. next hop address. 

The interface for the route is the interface the packet came in on.

The routes learnt from this are __higher priority routes__. Create a separate forwarding table called *dynamic_routing_table*. 

The size of this table should be set to 5.

1. In addition to Arp and IPv4 packets you should now also accept DynamicRoutingMessage packets.

2. Everytime you receive this packet you can update your routing table to store these routes. If there is no space in the table, remove the oldest route. (**First In First Out - FIFO**) The route lookup logic for this remains same as forwarding table which uses the Longest Prefix Match (LPM) described above.

3. When you get an IPv4 packet which should be routed, now first look for a match in dynamic_routing_table. If present (breaking ties by lpm), use that else go to 4.

4. Look in the forwarding_table (previously created in part2, again break ties by lpm). If present, use that.

## Part 4: Mininet live testing