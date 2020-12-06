import scapy.all as scapy
import sys

def arpCheck(incomingIP, incomingMAC):

    #pinging the the IP we want to check
    icmp = scapy.IP(dst=incomingIP)/scapy.ICMP()
    request = scapy.ARP()
    resp = scapy.sr1(icmp,timeout=1)
    if resp != None:
        request.pdst = incomingIP
        broadcast = scapy.Ether()

        broadcast.dst = 'ff:ff:ff:ff:ff:ff'

        request_broadcast = broadcast / request
        clients = scapy.srp(request_broadcast, timeout = 1)[0]

        # for element in clients:
            # print(element[1].psrc + "      " + element[1].hwsrc)

        for element in clients:
            print(incomingMAC)
            print(element[1].hwsrc)
            if(element[1].psrc == incomingIP and element[1].hwsrc == incomingMAC):
                # print("IP: " + incomingIP + " with MAC: " + incomingMAC + " is not spoofed.")
                return True
            else:
                # print("IP: " + incomingIP + " with MAC: " + incomingMAC + " is spoofed.")
                return False
    #else:  
    #    print("Host is Down, not going to check ARP")


print(arpCheck('192.168.1.14', '22:86:98:39:90:39'))
