class PktQueue:

    def __init__(self):
        self.entryList = []

    class Entry:
        def __init__(self, last_req_time, num_retry, pkt):
            self.last_req_time = last_req_time
            self.num_retry = num_retry
            self.pkt = pkt

    def addEntry(self, last_req_time, num_retry, pkt):
        entry = self.Entry(last_req_time, num_retry, pkt)
        self.entryList.append(entry)

    # find the matched entry using arp_reply
    def findMatch(self, arp_reply):
        for i in range(len(self.entryList)):
            # Destination IP of packet matches the sender IP from ARP reply
            entry = self.entryList[i]
            if entry.pkt.dstip == arp_reply.senderprotoaddr:
                entry = self.entryList.pop(i)
                return entry.pkt
        return None
    # Print the table for debugging purposes
    def printTable(self):
        for entry in self.entryList:
            log_debug(entry.last_req_time + " " + entry.num_retry + " " + entry.pkt.dstip)


# The classes below are just for testing purposes
class Packet:
    def __init__(self, dstip):
        self.dstip = dstip

class Arp_reply:
    def __init__(self, senderprotoaddr):
        self.senderprotoaddr = senderprotoaddr


