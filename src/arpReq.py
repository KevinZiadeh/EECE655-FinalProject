import scapy.all as scapy
import sys

def getReferenceMACandIPs():
    fl = open("packets/IPandMAC.txt", "r")
    IPs = []
    MACs = []
    for line in fl:
        stripped_line = line.strip()
        strippedList = line.split(' ')
        IPs.append(strippedList[0])
        MACs.append(strippedList[1])
    return IPs, MACs

def arpCheck(incomingIP):
    #pinging the the IP we want to check
    refIP, refMAC = getReferenceMACandIPs()
    print(refIP)
    print(refMAC)
    request = scapy.ARP()
    request.pdst = incomingIP
    broadcast = scapy.Ether()

    broadcast.dst = 'ff:ff:ff:ff:ff:ff'

    request_broadcast = broadcast / request
    clients = scapy.srp(request_broadcast, timeout = 1)[0]

    # for element in clients:
        # print(element[1].psrc + "      " + element[1].hwsrc)

    for element in clients:
        if element[1].psrc in refIP:
            index = refIP.index(element[1].psrc)
            if(element[1].hwsrc == refMAC[index]):
                print("IP "+element[1].psrc +" has reference MAC "+refMAC[index]+"\n")
            else:
                print("IP "+element[1].psrc +" has MAC "+element[1].hwsrc+" which is different from ref MAC "+refMAC[index]+"\n")
#else:  
#    print("Host is Down, not going to check ARP")

arpCheck('192.168.1.1/24')
