import scapy.all as scapy
import sys
import numpy as np
import matplotlib.pyplot as plt

def getReferenceMACandIPs():
    fl = open("src/packets/IPandMACReference.txt", "r")
    IPs = []
    MACs = []
    for line in fl:
        stripped_line = line.strip()
        strippedList = line.split(' ')
        IPs.append(strippedList[0])
        MACs.append(strippedList[1])
    return IPs, MACs

def getCurrentMACandIPs():
    fl = open("src/packets/IPandMACSpoofed.txt", "r")
    IPs = []
    MACs = []
    for line in fl:
        stripped_line = line.strip()
        strippedList = line.split(' ')
        IPs.append(strippedList[0])
        MACs.append(strippedList[1])
    return IPs, MACs

def doTablePlot(x,y, title, val):
    val1 = ["IP Address", "MAC Address"] 
    val2 = [("Host #"+ str(i+1)) for i in range(5)]
    listofLists = []
    for i in range(5):
        element = []
        element.append(x[i])
        element.append(y[i].strip("\n"))
        listofLists.extend([element])
        print(element)
    val3 = listofLists
    fig, ax = plt.subplots() 

    rcolors = plt.cm.BuPu(np.full(5, 0.1))
    ccolors = plt.cm.BuPu(np.full(2, 0.1))

    elementColors = []
    for index in range(5):
        if val == index:
            elementColors.append(["#ff4040","#ff4040"])
        else:
            elementColors.append(["#90EE90","#90EE90"])

    table = ax.table( 
        cellText = val3,  
        rowLabels = val2,  
        colLabels = val1, 
        cellLoc ='center',
        cellColours=elementColors,
        colColours=ccolors,
        rowColours=rcolors,  
        loc ='upper left')
            
    ax.set_title(title, fontweight ="bold") 
    ax.set_axis_off() 
    plt.show() 

def arpCheck():
    #pinging the the IP we want to check
    refIP, refMAC = getReferenceMACandIPs()
    IP, MAC = getCurrentMACandIPs()
    


    #request = scapy.ARP()
    #request.pdst = incomingIP
    #broadcast = scapy.Ether()

   #broadcast.dst = 'ff:ff:ff:ff:ff:ff'

    #request_broadcast = broadcast / request
    #clients = scapy.srp(request_broadcast, timeout = 1)[0]

    # for element in clients:
        # print(element[1].psrc + "      " + element[1].hwsrc)
    declared = 0
    print("\n")
    for ipAddress in IP:
        if ipAddress in refIP:
            index = refIP.index(ipAddress)
            if(MAC[index] == refMAC[index]):
                print("IP "+ ipAddress +" has reference MAC " + refMAC[index] + "\n")
            else:
                declared = index
                print("IP "+ ipAddress +" has MAC "+ MAC[index] +" which is different from ref MAC "+refMAC[index]+"\n")
    
    doTablePlot(refIP,refMAC, "Hosts Information / No MAC Spoofing", -1)
    doTablePlot(IP,MAC, "Hosts Information / With MAC Spoofing", declared)
#else:  
#    print("Host is Down, not going to check ARP")