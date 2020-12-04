'''
Import OS to detect windows or Linux
    command = "ip neigh" arp table on linux
    command = "arp -a" arp table on Windows


import requests

def get_info(mac_address):
	return requests.get("https://macvendors.co/api/vendorname/"+mac_address+"/").text
'''

# commandOutput = str(subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)).split('\\n')
# routerIP = commandOutput[0].split()[0][2:]
# routerMAC = commandOutput[0].split()[4]


# commandOutput = out.split('\\r\\n')
# routerIP = commandOutput[3].split()[0]
# routerMAC = commandOutput[3].split(