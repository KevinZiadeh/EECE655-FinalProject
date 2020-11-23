import json
from matplotlib import pyplot as plt
from scapy.all import *

import jsonPacket as jsP
import pcapPacket as pcapP

'''
Used wireshark with NIC in monitor mode to get pcapng file. Make sure decryption of IEEE 802.11 is enabled and working
Used wireshark extract as json to get json file

JSON file size is way bigger than pcap
PCAP execution time is way greater
'''


# calculate the gap between two consecutive sequence numbers
def calculateGap(seqList):
    gapList = []
    for i in range(1, len(seqList)):
        # handle loop around case
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


# plot graphs for every client with respect to the parameter (seqGap, RSS?)
def plot(client, name):
    seqnum = client["seqGap"]
    signal = client["sigGap"]

    plt.subplot(2, 2, 1)
    plt.scatter([i for i in range(1, (len(seqnum)) * 100, 100)], seqnum, s=0.1)
    plt.ylim((0, 4096))
    plt.yticks([i for i in range(0, 4096, 500)], [i for i in range(0, 4096, 500)])
    plt.title(name+": Sequence Number")


    plt.subplot(2, 2, 2)
    plt.scatter([i for i in range(1, (len(signal)) * 100, 100)], signal, s=0.1)
    plt.ylim((0, 70))
    plt.yticks([i for i in range(0, 70, 10)], [i for i in range(0, 70, 10)])
    plt.title(name+": Signal Strength")

    x, y = zip(*client["seqPer"])
    plt.subplot(2, 2, 3)
    plt.plot(x, y)
    plt.ylim((0, 1))
    plt.title(name+": Sequence Number Percentage")

    x, y = zip(*client["sigPer"])
    plt.subplot(2, 2, 4)
    plt.plot(x, y)
    plt.ylim((0, 1))
    plt.title(name+": Signal Strength Percentage")

    plt.show()


# filter clients to get only ones with enough packets to matter
def filterClients(clients):
    newClients = {}
    for client in clients:
        if len(clients[client]["seqNum"])>50 and clients[client]["seqNum"][0] is not None and clients[client]["sigStr"][0] is not None:
            newClients[client] = clients[client]
            newClients[client]["seqGap"] = calculateGap(newClients[client]["seqNum"])
            newClients[client]["sigGap"] = calculateGap(newClients[client]["sigStr"])
            newClients[client]["seqPer"] = calculatePercentages(newClients[client]["seqGap"])
            newClients[client]["sigPer"] = calculatePercentages(newClients[client]["sigGap"])
            newClients[client]["warning"] = 0
    return newClients


'''
Gives initial warning to captured clients
seqGap
    If the gap ig greater than 3, then it is ouside the window and abnormal
    If the gap is between 1 and 3, then it is a normal inside the window packet
    If the gap is 0 or very large, check if it is a retransmission 
sigGap
    If the gap a greater than a threshold, flag as abnormal
    
Hyperparameters (addition numbers) were selected using trial and error
'''
def initialWarning(clients):
    for key in clients:
        c = 0
        for i in range(len(clients[key]["seqGap"])):
            gap = clients[key]["seqGap"][i]
            currentSN = clients[key]["seqNum"][(i+1)%4096]
            if gap > 0 or gap < 4:
                clients[key]["warning"] -= 1
            elif gap == 0 or gap > 4093: # duplicate
                previous1SN = clients[key]["seqNum"][(i)%4096]
                previous2SN = clients[key]["seqNum"][(i-1)%4096]
                previous3SN = clients[key]["seqNum"][(i-2)%4096]
                previous4SN = clients[key]["seqNum"][(i-3)%4096]
                if currentSN != previous1SN and currentSN != previous2SN and currentSN != previous3SN and currentSN != previous4SN:
                    clients[key]["warning"] += 10
            else:
                clients[key]["warning"] += 10

        for i in range(len(clients[key]["sigGap"])):
            gap = clients[key]["sigGap"][i]
            if gap > 5:
                clients[key]["warning"] += 10
            else:
                clients[key]["warning"] -= 1


def spoofDetection(client, packet):
    pass


if __name__ == '__main__':
    # if we are using json - takes 3-7 minutes
    # with open('./res/test3.json') as f:
    #     jsonfile = json.load(f)
    # clients = jsP.getClients(jsonfile)

    # if we are using pcap - takes 7-10 minutes
    capfile = rdpcap('./res/test-03.pcapng')
    clients = pcapP.getClients(capfile)

    clients = filterClients(clients)

    initialWarning(clients)

    for client in clients:
        print(clients[client]["warning"]/len(clients[client]["seqNum"]))
        '''
        Above 0.5 will be flagged
        Output was : 
        -1.8831740910782975
        0.06343258159024323
        -1.0209580838323353
        -1.898404367487523
        -1.9839253056117048
        -1.9410609037328095
        -1.3796844181459567
        -1.7876106194690264
        -0.7375
        '''
    # for client in clients:
    #     plot(clients[client], client)
