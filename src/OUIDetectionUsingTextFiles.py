from scapy.all import ARP, Ether, srp
import requests
import numpy as np
import matplotlib.pyplot as plt
import math

def getWhiteList():
    whitelistFile = open("whitelist.txt", "r")
    whitelistElements = []
    for line in whitelistFile:
        stripped_line = line.strip()
        whitelistElements.append(stripped_line)
    return whitelistElements

def get_info(mac_address):
    return requests.get("https://macvendors.co/api/vendorname/"+mac_address+"/").text

def scanPacketFile(filename):
    packets = open(filename, "r")

    MACelements = []
    for line in packets:
        stripped_line = line.strip()
        stripped_line = stripped_line.split(" ")
        MACelements.append(stripped_line[0])
    return list(dict.fromkeys(MACelements))

def getVendor(MACResults):

    vendorWhitelist = getWhiteList()
    VendorList = []

    for MACAddress in MACResults :
        vendorName = get_info(MACAddress)
        VendorList.append(vendorName)

        if vendorName == "No vendor" :
            print(str(MACAddress)+" : No vendor \n")
            
        
        elif (vendorName not in vendorWhitelist) :
            print(str(MACAddress)+": Not in whitelist, vendor "+ vendorName+ "\n")
        
        else:
            print(str(MACAddress)+" : In Whitelist, vendor "+ vendorName+ " \n")

    sortedVendorList = []
    qtyOfDevices = []

    for vendor in VendorList:
        if vendor not in sortedVendorList:
            sortedVendorList.append(vendor)
            qtyOfDevices.append(VendorList.count(vendor))

    qtyOfDevices[1],qtyOfDevices[3] = qtyOfDevices[3],qtyOfDevices[1]
    sortedVendorList[1],sortedVendorList[3] = sortedVendorList[3],sortedVendorList[1]

    return sortedVendorList,qtyOfDevices

def getVendorBarPlot(MACResults):

    vendorWhitelist = getWhiteList()
    VendorList = []

    for MACAddress in MACResults :
        vendorName = get_info(MACAddress)
        VendorList.append(vendorName)

        if vendorName == "No vendor" :
            print(str(MACAddress)+" : No vendor \n")
            
        
        elif (vendorName not in vendorWhitelist) :
            print(str(MACAddress)+": Not in whitelist, vendor "+ vendorName+ "\n")
        
        else:
            print(str(MACAddress)+" : In Whitelist, vendor "+ vendorName+ " \n")

    return VendorList
 
def doGraphPlot(x,y, val):
    plt.style.use('default')

    x_pos = [i for i, _ in enumerate(x)]
    if val == 0 :
        plt.bar(x_pos, y)
    else:
        colors = ['#1f77b4','#1f77b4','#1f77b4','brown']
        plt.bar(x_pos, y, color = colors)
    
    plt.xlabel("Vendor")
    plt.ylabel("Number of Devices")
    plt.title("")

    plt.xticks(x_pos, x)
    yint = range(min(y), math.ceil(max(y))+1)

    plt.yticks(yint)

    plt.show()

def doTablePlot(x,y, title):
    val1 = ["MAC Address", "Associated Vendor"] 
    val2 = [("Host #"+ str(i+1)) for i in range(5)]
    listofLists = []
    for i in range(5):
        element = []
        element.append(x[i])
        element.append(y[i])
        listofLists.extend([element])
        print(element)
    val3 = listofLists
    fig, ax = plt.subplots() 

    rcolors = plt.cm.BuPu(np.full(5, 0.1))
    ccolors = plt.cm.BuPu(np.full(2, 0.1))
    elementColors = [["#90EE90","#90EE90"],["#ff4040","#ff4040"], ["#90EE90","#90EE90"], ["#90EE90","#90EE90"], ["#90EE90","#90EE90"]]

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


MACResults1 = scanPacketFile('packets/SniffedPacketsForOUI.txt')
x,y = getVendor(MACResults1)
doGraphPlot(x,y,1)
vendorsList = getVendorBarPlot(MACResults1)
doTablePlot(MACResults1,vendorsList,'Reference / No Spoofing')

MACResults2 = scanPacketFile('packets/SniffedPacketsSpoofed1ForOUI.txt')
x,y = getVendor(MACResults2)
doGraphPlot(x,y,1)
vendorsList = getVendorBarPlot(MACResults2)
doTablePlot(MACResults2,vendorsList,'MAC Spoofing / Non-valid MAC Address')

MACResults3 = scanPacketFile('packets/SniffedPacketsSpoofed2ForOUI.txt')
x,y = getVendor(MACResults3)
doGraphPlot(x,y,1)
vendorsList = getVendorBarPlot(MACResults3)
doTablePlot(MACResults3,vendorsList,'MAC Spoofing / Valid MAC Address & Non-Whitelisted')