import json
from matplotlib import pyplot as plt
from scapy.all import *

'''
Used wireshark with NIC in monitor mode to get pcapng file. Used wireshark extract as json to get json file
'''

# sequence number can appear in two places depending on the type of packet
def getSequenceNumber(wlan):
    if "wlan.seq" in wlan:
        return wlan["wlan.seq"]
    elif "Compressed BlockAck Response" in wlan:
        return wlan["Compressed BlockAck Response"]["wlan.fixed.ssc_tree"]["wlan.fixed.ssc.sequence"]

# calculate the gap between two consecutive sequence numbers
def calculateGap(seqList):
    gapList = []
    for i in range(1, len(seqList)):
        if seqList[i]<4093:
            gapList.append(abs(seqList[i]-seqList[i-1]))
        else:
            gapList.append(abs(-(4096-(seqList[i] - seqList[i - 1]))))
    return gapList

# calculate percentage of each value appearing
def calculatePercentages(seqList):
    seqDict = {}
    for e in seqList:
        if e not in seqDict:
            seqDict[e] = 1
        else:
            seqDict[e] += 1
    for key in seqDict:
        if seqDict[key] < 10^-2:
            seqDict.pop(key)
        else:
            seqDict[key] = seqDict[key]/len(seqList)

    PerList = sorted(seqDict.items()) # sort by key

    return PerList

# extract from packets that contain a sequence number the clients as well as the sequence number
def getClients(jsonfile):
    clients = {}
    for packet in jsonfile:
        wlan = packet["_source"]["layers"]
        if "wlan.sa" in wlan["wlan"]:
            source = wlan["wlan"]["wlan.sa"]
            if source in clients:
                clients[source]["seqNum"].append(int(getSequenceNumber(wlan["wlan"])))
                if "wlan_radio" in wlan and "wlan_radio.signal_dbm" in wlan["wlan_radio"]:
                    clients[source]["sigStr"].append(int(wlan["wlan_radio"]["wlan_radio.signal_dbm"]))
            else:
                clients[source] = {}
                clients[source]["seqNum"] = []
                clients[source]["sigStr"] = []

    # filter clients to get only ones with enough packets to matter
    for key in clients:
        if len(clients[key]["seqNum"])>50:
            clients[key]["seqGap"] = calculateGap(clients[key]["seqNum"])
            clients[key]["sigGap"] = calculateGap(clients[key]["sigStr"])
    return clients

# plot graphs for every client with respect to the parameter (seqGap, RSS?)
def plot(client, name):
    seqnum = client["seqGap"]
    signal = client["sigGap"]

    seqPer = calculatePercentages(seqnum)
    sigPer = calculatePercentages(signal)

    plt.subplot(2, 2, 1)
    plt.scatter([i for i in range(1, (len(seqnum)) * 100, 100)], seqnum, s=0.1)
    plt.ylim((0, 4096))
    plt.yticks([i for i in range(0, 4096, 500)], [i for i in range(0, 4096, 500)])
    plt.title(name+": Sequence Number")


    plt.subplot(2, 2, 2)
    plt.scatter([i for i in range(1, (len(signal)) * 100, 100)], signal, s=0.1)
    plt.ylim((0, 70))
    plt.yticks([i for i in range(0, 50, 70)], [i for i in range(0, 70, 10)])
    plt.title(name+": Signal Strength")


    x, y = zip(*seqPer)
    plt.subplot(2, 2, 3)
    plt.plot(x, y)
    plt.ylim((0, 1))
    plt.title(name+": Sequence Number Percentage")

    x, y = zip(*sigPer)
    plt.subplot(2, 2, 4)
    plt.plot(x, y)
    plt.ylim((0, 1))
    plt.title(name+": Signal Strength Percentage")

    plt.show()

def spoofDetection():
    pass


if __name__ == '__main__':
    with open('./res/test3.json') as f:
        jsonfile = json.load(f)
    clients = getClients(jsonfile)

    '''
    to directly extract info from .pcap file
    '''
    # capfile = rdpcap('./test-03.pcapng')
    # print(capfile[3]["RadioTap"].dBm_AntSignal)
    # print(int(capfile[3]["802.11-FCS"].SC)/(2^4))
    # print(capfile[3]["802.11-FCS"].addr1)

    for client in clients:
        plot(clients[client], client)
        break