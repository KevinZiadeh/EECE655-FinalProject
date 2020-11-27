def getClients(txtfile):
    clients = {}
    for line in txtfile:
        lineList = line.split()
        (sa, sn, ss) = lineList[0], int(lineList[1]), int(lineList[2])
        if sa in clients:
            clients[sa]["seqNum"].append(sn)
            clients[sa]["sigStr"].append(ss)
        else:
            clients[sa] = {}
            clients[sa]["seqNum"] = []
            clients[sa]["sigStr"] = []
    return clients

def extractPacket(packet):
    lineList = packet.split()
    (sa, sn, ss) = lineList[0], int(lineList[1]), int(lineList[2])
    return lineList[0], int(lineList[1]), int(lineList[2])