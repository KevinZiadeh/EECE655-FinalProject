import subprocess
from scapy.all import *
import argparse
import re
import settings

# Enable Promiscuous Mode on a specific interface
from src import SNaSSCheck


def enablePromiscuousMode(interface):
    # subprocess.run(["sudo", "ifconfig", interface, "promisc"])
    # iw <interface> interface add <new_interface> type monitor creates a new interface is monitor mode

    subprocess.run(["ifconfig", interface, "down"])
    subprocess.run(["iwconfig", interface, "mode", "monitor"])
    subprocess.run(["ifconfig", interface, "up"])
    print("Enabling Promiscuous Mode...\n")

# Disable Promiscuous Mode on a specific interface
def disablePromiscuousMode(interface):
    # subprocess.run(["sudo", "ifconfig", interface, "-promisc"])
    subprocess.run(["ifconfig", interface, "down"])
    subprocess.run(["iwconfig", interface, "mode", "managed"])
    subprocess.run(["ifconfig", interface, "up"])

    print("\nDisabling Promiscuous Mode...\n")

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
# We wait for user input before stopping packet sniffing
def persistent_packet_sniffing(interface):
    print("Sniffing packets on interface", interface,", press Ctrl+C to stop...\n")
    
    packets = sniff(iface=interface,  monitor=True)


    # Print out the summary of all the packets sniffed, and return them
    #packets.nsummary()
    return packets

# Output Packet Sniffing results to an output file 'packetSniffingResults.txt'
def resultOutput(packets):
    if len(packets) == 0:
        return
    
    
    with open('src/packets/SniffedPackets.txt', 'a') as f:
        for i in range(len(packets)):
            #f.write(packets[i].show(dump=True))
            srcMACAddress = packets[i].addr2 if packets[i].addr2 is not None else None
            sc = packets[i].SC//2**4 if packets[i].SC is not None else None
            rdtap = packets[i].dBm_AntSignal
            if srcMACAddress is not None and sc is not None and rdtap is not None:
                packetData = str(srcMACAddress) + " " + str(sc) + " " + str(rdtap) + "\n"
                f.write(packetData)

        print("\nSniffed packets are available in SniffedPackets.txt")
        f.close()

def dynamicPacket(packet):
    srcMACAddress = packet.addr2 if packet.addr2 is not None else None
    sc = packet.SC // 2 ** 4 if packet.SC is not None else None
    rdtap = packet.dBm_AntSignal
    if srcMACAddress is not None and sc is not None and rdtap is not None:
        with open('src/packets/SniffedPackets.txt', 'a') as f:
            packetData = str(srcMACAddress) + " " + str(sc) + " " + str(rdtap) + "\n"
            f.write(packetData)
        SNaSSCheck.spoofDetection(packetData)


if __name__ == "__main__":

    # List all interfaces available on the host
    interface_choices = listHostInterfaces()

    # Parse arguments passed to the Python script
    parser = argparse.ArgumentParser()
    parser.add_argument("interface", choices=interface_choices, help="Interface name")
    parser.add_argument("-p", "--persistent", action="store_true", help="Enable persistent packet sniffing")


    args = parser.parse_args()

    # Enable Promiscuous mode
    enablePromiscuousMode(args.interface)

    # Enable persistent packet sniffing
    # Else, sniff a specific amount of packets
    if args.persistent:
        packets = persistent_packet_sniffing(interface=args.interface)
        resultOutput(packets)
    else:
        settings.init()
        sniff(iface=args.interface, prn = dynamicPacket)
        print('\n')
        for client in settings.clients:
            print(client + " warning: "+ str(settings.clients[client]["warning"]/len(settings.clients[client]["seqNum"])))

    # Disable Promiscuous mode
    disablePromiscuousMode(args.interface)