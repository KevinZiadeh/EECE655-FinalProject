import json
import argparse

    
def get_manufacturer_name(manufacturer):
    return manufacturer.get('companyName')

def get_manufacturer_oui(manufacturer):
    return manufacturer.get('oui')

parser = argparse.ArgumentParser()
parser.add_argument("MAC_Address", type=str, help="MAC Address to verify the OUI for")
args = parser.parse_args()

manufacturerList = []
with open('macaddress.io-db.json') as f:
    for jsonObj in f:
        manufacturerDict = json.loads(jsonObj)
        manufacturerList.append(manufacturerDict)

for i in manufacturerList:
    if i['oui'] == args.MAC_Address.upper() :
        print("MAC Manufacturer match : " + i['oui']+" "+i['companyName']+"\n")
