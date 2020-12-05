from scapy.all import ARP, Ether, srp
import argparse
import requests

def getWhiteList():
    whitelistFile = open("whitelist.txt", "r")
    whitelistElements = []
    for line in whitelistFile:
        stripped_line = line.strip()
        whitelistElements.append(stripped_line)
    return whitelistElements

def get_info(mac_address):
    return requests.get("https://macvendors.co/api/vendorname/"+mac_address+"/").text

def scanSubnet(ip): 
    arp_pkt= Ether()/ARP()
    arp_pkt[ARP].pdst = ip
    arp_pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"

    response = srp(arp_pkt,timeout=6, verbose=0)[0] 
    hostsIPs = []
    hostsMACs = []
    for sent, received in response: 
        hostsIPs.append(received.psrc)
        hostsMACs.append(received.src)
    return hostsIPs, hostsMACs

parser = argparse.ArgumentParser()
parser.add_argument("subnet", type=str, help="Cidr Notation of Subnet to check")
args = parser.parse_args()

IPResults, MACResults = scanSubnet(args.subnet)


vendorWhitelist = getWhiteList()

trackValue = 0
for MACAddress in MACResults :
    vendorName = get_info(MACAddress)

    if vendorName == "No vendor" :
        print(str(IPResults[trackValue])+"/"+str(MACResults[trackValue])+" is not registered with any vendor. It is invalid & probably spoofed \n")
    
    elif (vendorName not in vendorWhitelist) :
        print(str(IPResults[trackValue])+"/"+str(MACResults[trackValue])+" is "+ vendorName+ " which is not in our vendor whitelist. It is probably spoofed \n")
    
    else:
        print("Vendor for "+str(IPResults[trackValue])+"/"+str(MACResults[trackValue])+" is "+vendorName+"\n")
    trackValue += 1