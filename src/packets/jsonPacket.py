# sequence number can appear in two places depending on the type of packet
def getSequenceNumber(wlan):
    if "wlan.seq" in wlan:
        return wlan["wlan.seq"]
    elif "Compressed BlockAck Response" in wlan:
        return wlan["Compressed BlockAck Response"]["wlan.fixed.ssc_tree"]["wlan.fixed.ssc.sequence"]


# extract from packets that contain a sequence number the clients as well as the sequence number
def getClients(jsonfile):
    clients = {}
    for packet in jsonfile:
        wlan = packet["_source"]["layers"]
        if "wlan.sa" in wlan["wlan"]:
            source = wlan["wlan"]["wlan.sa"]
            if source in clients:
                clients[source]["seqNum"].append(int(getSequenceNumber(wlan["wlan"])))
                if "wlan_radio" in wlan and "wlan_radio.signal_dbm" in wlan["wlan_radio"]:
                    clients[source]["sigStr"].append(int(wlan["wlan_radio"]["wlan_radio.signal_dbm"]))
            else:
                clients[source] = {}
                clients[source]["seqNum"] = []
                clients[source]["sigStr"] = []
    return clients

