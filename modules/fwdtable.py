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


        



