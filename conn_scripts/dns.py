import struct

class DNS:

    def __init__(self, raw_data):
        (self.id, self.flags, self.qdcount, self.ancount, self.nscount, self.arcount) = struct.unpack('! H H H H H H', raw_data[:12])
        self.data = raw_data[12:]