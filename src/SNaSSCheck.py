# from main import *
from src.packets import txtPacket as txtP
import settings
from src.SNaSSInitialize import plot, calculatePercentages, sequenceNumberWarning

# def spoofDetection(settings.clients, packet):
def spoofDetection(packet):
    (sa, sn, ss) = txtP.extractPacket(packet)
    # compute missing parameters
    if sa in settings.clients:
        if sn < 4093:
            seqgap = abs(sn - settings.clients[sa]["seqNum"][-1])
        else:
            seqgap = abs(-(4096 - (sn - settings.clients[sa]["seqNum"][-1])))
        siggap = abs(ss - settings.clients[sa]["sigStr"][-1])
        # update client
        settings.clients[sa]["seqNum"].append(sn)
        settings.clients[sa]["sigStr"].append(ss)
        settings.clients[sa]["seqGap"].append(seqgap)
        settings.clients[sa]["sigGap"].append(siggap)
        settings.clients[sa]["seqPer"] = calculatePercentages(settings.clients[sa]["seqGap"])
        settings.clients[sa]["sigPer"] = calculatePercentages(settings.clients[sa]["sigGap"])
        settings.clients[sa]["warning"] += sequenceNumberWarning(settings.clients[sa], seqgap, sn, len(settings.clients[sa]["seqNum"])-1)
        settings.clients[sa]["warning"] = (settings.clients[sa]["warning"]+10) if siggap > 5 else (settings.clients[sa]["warning"]-1)
        if settings.clients[sa]["warning"] / len(settings.clients[sa]["seqNum"]) > 0.1:
            print(sa + "might be a spoofed mac address")
            decision = input("Plot figure? (y yes, n no)").lower()
            if decision == "y":
                plot(settings.clients[sa], sa)
    else:
        settings.clients[sa] = {}
        settings.clients[sa]["seqNum"] = [sn]
        settings.clients[sa]["sigStr"] = [ss]
        settings.clients[sa]["seqGap"] = []
        settings.clients[sa]["sigGap"] = []
        settings.clients[sa]["warning"] = 0
