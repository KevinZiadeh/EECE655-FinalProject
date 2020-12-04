import json
import argparse
import requests

# MAC address given as an argument should be in the format 'XX:XX:XX:XX:XX:XX'
parser = argparse.ArgumentParser()
parser.add_argument("MAC_Address", type=str, help="MAC Address to verify the OUI for")
args = parser.parse_args()

def get_info(mac_address):
	return requests.get("https://macvendors.co/api/vendorname/"+mac_address+"/").text

vendorName = get_info(args.MAC_Address.upper())
print(vendorName)