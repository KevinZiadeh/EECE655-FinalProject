from src import OUIDetectionUsingTextFiles
from src import arpReq
from src import SNaSSInitialize
import settings

# Execute Sequence Number and Signal Strength
SNaSSInitialize.initialize('src/packets/SniffedPacketsSpoofed.txt')
# SNaSSInitialize.initialize('src/packets/SniffedPackets.txt')
for sa in settings.clients:
    if settings.clients[sa]["warning"] > -0.2 and (len(settings.clients[sa]["seqNum"])) > 100:
        print(sa + "is most definetely a spoofed mac address")
        decision = input("Plot figure? (y yes, n no)").lower()
        if decision == "y":
            SNaSSInitialize.plot(settings.clients[sa], sa)
    elif settings.clients[sa]["warning"] > -1 and (len(settings.clients[sa]["seqNum"])) > 100:
        print(sa + "might be a spoofed mac address")
        decision = input("Plot figure? (y yes, n no)").lower()
        if decision == "y":
            SNaSSInitialize.plot(settings.clients[sa], sa)

# Execute OUI Detection
# OUIDetectionUsingTextFiles.executeSimulation()

# Execute ARP Detection
# arpReq.arpCheck()