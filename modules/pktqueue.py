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


# The classes below are just for testing purposes
class Packet:
    def __init__(self, dstip):
        self.dstip = dstip

class Arp_reply:
    def __init__(self, senderprotoaddr):
        self.senderprotoaddr = senderprotoaddr


