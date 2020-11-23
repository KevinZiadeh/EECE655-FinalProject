import subprocess
from scapy.all import *
import argparse
import re
import json

# Enable Promiscuous Mode on a specific interface
def enablePromiscuousMode(interface):
    subprocess.run(["sudo", "ifconfig", interface, "promisc"])
    print("Enabling Promiscuous Mode...\n")

# Disable Promiscuous Mode on a specific interface
def disablePromiscuousMode(interface):
    subprocess.run(["sudo", "ifconfig", interface, "-promisc"])
    print("Disabling Promiscuous Mode...\n")

# List all network interfaces available on the host machine
def listHostInterfaces():
    interface_txt = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
    extractedInterfaces = re.findall("(^[1-9].*:)|(\n[1-9].*:)", interface_txt.stdout)

    interface_choices = []
    for t in extractedInterfaces:
	    if t[0]:
		    interface_choices.append(t[0].split()[1][:-1])
	    else:
		    interface_choices.append(t[1].split()[1][:-1])

    return interface_choices

# Sniff packets that satisfy filters on our specific interface
# We sniff a certain amount of packet before stopping
def sniff_packets(interface, count, filter):
    print("Sniffing", count, "packets on interface", interface,"...\n")
    packets = sniff(iface=interface, count=count, filter=filter, monitor=True)

    #Print out the summary of all the packets sniffed, and return them
    packets.nsummary()
    return packets

# Sniff packets that satisfy filters on our specific interface
# We wait for user input before stopping packet sniffing
def persistent_packet_sniffing(interface, filter):
    print("Sniffing packets on interface", interface,", press any key to stop...\n")
    packets = sniff(iface=interface, filter=filter, monitor=True)

    # Print out the summary of all the packets sniffed, and return them
    packets.nsummary()
    return packets

# Output Packet Sniffing results to an output file 'packetSniffingResults.txt'
def resultOutput(packets):
    if len(packets) == 0:
        return
    
    with open('packetSniffingResults.json', 'w') as f:
        PacketList = []
        for i in range(len(packets)):
            #f.write(packets[i].show(dump=True))
            if packets[i].getlayer('Ethernet') is not None and packets[i].getlayer('TCP') is not None:
                srcMACAddress = packets[i].getlayer('Ethernet').src
                TCPsqn = packets[i].getlayer('TCP').seq
                packetData = {}
                if packets[i].getlayer('Radiotap') is not None:
                    rdtap = packets[i].getlayer('Radiotap').dBm_AntSignal
                    packetData = {'SourceMACAddress': srcMACAddress, 'TCPSequenceNumber' : TCPsqn, "SignalStrength": rdtap}
                else:
                    packetData = {'SourceMACAddress': srcMACAddress, 'TCPSequenceNumber' : TCPsqn}
                PacketList.append(packetData)

        results = {'Packets' : PacketList}        
        json.dump(results, f,indent = 4, sort_keys=True)
        print("Sniffed packets are available in packetSniffingResults.txt")


if __name__ == "__main__":

    # List all interfaces available on the host
    interface_choices = listHostInterfaces()

    # Parse arguments passed to the Python script
    parser = argparse.ArgumentParser()
    parser.add_argument("interface", choices=interface_choices, help="Interface name")
    parser.add_argument("-c", "--count", type=int, default=100, help="Packet count")
    parser.add_argument("-f", "--filter", default='', help="Packet filter")
    parser.add_argument("-p", "--persistent", action="store_true", help="Enable persistent packet sniffing")
    parser.add_argument("-o", "--output", action="store_true", help="Write packet sniffing results to file")
    args = parser.parse_args()

    # Enable Promiscuous mode
    enablePromiscuousMode(args.interface)

    # If script was launched with flag '-p' or '--persistent'
    # Enable persistent packet sniffing
    # Else, sniff a specific amount of packets
    if args.persistent:
        packets = persistent_packet_sniffing(interface=args.interface, filter=args.filter)
    else:
        packets = sniff_packets(interface=args.interface, count=args.count, filter=args.filter)

    # If script was launched with flag '-o' or '--output'
    # Print packet sniffing results to output file
    if args.output:
        resultOutput(packets)
    
    # Disable Promiscuous mode
    disablePromiscuousMode(args.interface)
