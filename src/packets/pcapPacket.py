# sequence number can appear in two places depending on the type of packet
def getSourceAddress(packet):
    if not packet.addr3:
        return False
    return packet.addr2

# extract from packets that contain a sequence number the clients as well as the sequence number
def getClients(capfile):
    clients = {}
    for packet in capfile:
        (sa, sn, ss) = extractPacket(packet)
        if not sa or not sn or ss is None:
            continue
        else:
            if sa in clients:
                clients[sa]["seqNum"].append(sn)
                clients[sa]["sigStr"].append(ss)
            else:
                clients[sa] = {}
                clients[sa]["seqNum"] = []
                clients[sa]["sigStr"] = []
    return clients

def extractPacket(packet):
    ss = packet.dBm_AntSignal
    if not packet.SC:
        sn = False
    else:
        sn = packet.SC / (2 ** 4)  # packet.getlayer("Dot11").SC
    sa = getSourceAddress(packet)
    return (sa, sn, ss)