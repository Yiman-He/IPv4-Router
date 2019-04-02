class PktQueue:

    def __init__(self):
        self.entryList = []
        # This will map next_ip to a state.
        # 192.168.0.1 -> 0 means that we have not sent a request for this ip
        # 192.168.0.1 -> 1 means that we have already sent a request for this ip
        self.next_ip_set = {}

    class Entry:
        def __init__(self, last_req_time, num_retry, pkt, next_ip, intf_to_next):
            self.last_req_time = last_req_time
            self.num_retry = num_retry
            self.pkt = pkt
            self.next_ip = next_ip # This could etiher be the next hop ip or just dst ip
            self.intf_to_next = intf_to_next

    # Returns True or False
    # True means that next ip is already in queue, 
    # otherwise False
    def addEntry(self, pkt, next_ip, intf_to_next):
        last_req_time = time.time()
        num_retry = 1
        entry = self.Entry(last_req_time, num_retry, pkt, next_ip, intf_to_next)
        self.entryList.append(entry)
        if next_ip in next_ip_set:
            return True
        self.next_ip_set.add(next_ip)
        return False

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
                # Send arp request
                for intf in interfaces:
                    # Once we found the correct interface, just send the request
                    if intf.name == entry.intf_to_next:
                        senderhwaddr = intf.ethaddr
                        senderprotoaddr = intf.ipaddr
                        targetprotoaddr = entry.next_ip
                        arp_request = create_ip_arp_request(senderhwaddr, senderprotoaddr, targetprotoaddr)
                        net.send_packet(intf.name, arp_request)
                        # Add next_ip to the processed set
                        procd_next_ips.add(entry.next_ip)
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


