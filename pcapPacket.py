# sequence number can appear in two places depending on the type of packet
def getSourceAddress(packet):
    if not packet.addr3:
        return False
    return packet.addr2

# extract from packets that contain a sequence number the clients as well as the sequence number
def getClients(capfile):
    clients = {}
    # print("here")
    # print("packet")
    for packet in capfile:
        # print(packet)
        # break
        # if "dBm_AntSignal" in packet:
        #     ss = packet.dBm_AntSignal
        # else:
        #     continue
        # if "SC" in packet:
        #     sn = packet.SC/(2**4)
        # else:
        #     continue
        ss = packet.dBm_AntSignal
        if not packet.SC:
            continue
        sn = packet.SC / (2 ** 4) # packet.getlayer("Dot11").SC
        sa = getSourceAddress(packet)
        if not sa:
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
