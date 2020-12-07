from scapy.all import *

from src.packets import txtPacket as txtP
import settings
from matplotlib import pyplot as plt
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
        if seqList[i] < 4093:
            gapList.append(abs(seqList[i] - seqList[i - 1]))
        else:
            gapList.append(abs(-(4096 - (seqList[i] - seqList[i - 1]))))
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
        if seqDict[key] < 0.01:
            seqDict.pop(key)
        else:
            seqDict[key] = seqDict[key] / len(seqList)
    PerList = sorted(seqDict.items())  # sort by key
    return PerList


# plot graphs for every client with respect to the parameter (seqGap, RSS?)
def plot(client, name):
    seqnum = client["seqGap"]
    signal = client["sigGap"]

    plt.figure()
    plt.subplot(2, 2, 1)
    plt.scatter([i for i in range(1, (len(seqnum)) * 100, 100)], seqnum, s=0.15)
    plt.ylim((-5, 4096))
    plt.yticks([i for i in range(0, 4096, 500)], [i for i in range(0, 4096, 500)])
    plt.title(name + ": Sequence Number Gap")

    plt.subplot(2, 2, 2)
    plt.scatter([i for i in range(1, (len(signal)) * 100, 100)], signal, s=0.15)
    plt.ylim((-5, 70))
    plt.yticks([i for i in range(0, 70, 10)], [i for i in range(0, 70, 10)])
    plt.title(name + ": Signal Strength Gap")

    x, y = zip(*client["seqPer"])
    plt.subplot(2, 2, 3)
    plt.plot(x, y)
    plt.ylim((0, 1))
    plt.xlim((0, 9))
    plt.title(name + ": Sequence Number Percentage")

    x, y = zip(*client["sigPer"])
    plt.subplot(2, 2, 4)
    plt.plot(x, y)
    plt.ylim((0, 1))
    plt.xlim((0, 9))
    plt.title(name + ": Signal Strength Percentage")

    plt.show()


# filter clients to get only ones with enough packets to matter
def filterClients():
    newClients = {}
    for client in settings.clients:
        if len(settings.clients[client]["seqNum"]) > 100 and settings.clients[client]["seqNum"][0] is not None and \
                settings.clients[client]["sigStr"][0] is not None:
            newClients[client] = settings.clients[client]
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

# calculate warning with respect to sequence number gap. Takes client, gap and the packet number entry
def sequenceNumberWarning(client, gap, currentSN, i):
    if gap > 0 or gap < 4:
        return -1
    elif gap == 0 or gap > 4093:  # duplicate
        previous1SN = client["seqNum"][(i) % 4096]
        previous2SN = client["seqNum"][(i - 1) % 4096]
        previous3SN = client["seqNum"][(i - 2) % 4096]
        previous4SN = client["seqNum"][(i - 3) % 4096]
        if currentSN != previous1SN and currentSN != previous2SN and currentSN != previous3SN and currentSN != previous4SN:
            return 10
    else:
        return 10


def initialWarning():
    for key in settings.clients:
        for i in range(len(settings.clients[key]["seqGap"])):
            settings.clients[key]["warning"] += sequenceNumberWarning(settings.clients[key], settings.clients[key]["seqGap"][i],
                                                             settings.clients[key]["seqNum"][(i + 1) % 4096], i)

        for i in range(len(settings.clients[key]["sigGap"])):
            gap = settings.clients[key]["sigGap"][i]
            if gap > 5:
                settings.clients[key]["warning"] += 10
            else:
                settings.clients[key]["warning"] -= 1
        settings.clients[key]["warning"] = settings.clients[key]["warning"]/len(settings.clients[key]["seqNum"])

def initialize(file='src/packets/SniffedPackets.txt'): #default sniffed packets file
    # if we are using json - takes 3-7 minutes
    # with open('./res/test3.json') as f:
    #     jsonfile = json.load(f)
    # clients = jsP.getClients(jsonfile)

    # if we are using pcap - takes 7-10 minutes
    # capfile = rdpcap('./res/test-03.pcapng')
    # clients = pcapP.getClients(capfile)

    packets = open(file, "r")
    # packets = open('src/packets/SniffedPackets.txt', "r")
    # packets = open('packets/SniffedPacketsSpoofed.txt', "r")
    # packets = open('packets/SniffedPackets.txt', "r")
    settings.clients = txtP.getClients(packets)
    settings.clients = filterClients()

    initialWarning()

    # return settings.clients
    # for client in settings.clients:
    #     print(settings.clients[client]["warning"])
    #     plot(settings.clients[client], client)
    #     break
    '''
    Above -1 will be flagged as might
    Above -0.2 is most definetely 
    Output was : 
    -1.8831740910782975
    -1.0209580838323353
    -1.898404367487523
    -1.9839253056117048
    -1.9410609037328095
    -1.3796844181459567
    -1.7876106194690264
    -1.6682690063938022
    Mean: -1.69539
    Standard Deviation: 0.33463
    '''