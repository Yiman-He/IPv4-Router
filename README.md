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
3. For each ARP request, you should determine whether the *targetprotoaddr* field (IP address destination) in the ARP header is an IP address assigned to one of the interfaces on your router. (**Not sure if I can access assigned IP address through interface**)
    * If the destination IP address is one that is assigned to an interface of your Router, create and send an appropriate ARP reply. The ARP reply should be sent out of the same on which the ARP request arrived. (If the destination IP address is not assigned to one of the router's interfaces, drop the packet.)
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

## Part 3: Route information learning

## Part 4: Mininet live testing