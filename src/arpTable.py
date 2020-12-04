import subprocess
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("OS", type=str, help="OS you are currently using the script on (i.e. 'linux' for Linux and 'windows' for Windows")
args = parser.parse_args()

if args.OS == 'linux':
    commandOutput = str(subprocess.check_output("ip neigh", shell=True, stderr=subprocess.STDOUT)).split('\\n')
    #print(commandOutput)
    entryNumber = 0
    for entry in commandOutput:
        #print(entry)
        if entryNumber == 0 :
            routerIP = entry.split()[0][2:]
            routerMAC = entry.split()[4]
            print(routerIP)
            print(routerMAC)
        elif entryNumber != (len(commandOutput)-1):
            routerIP = entry.split()[0]
            routerMAC = entry.split()[4]
            print(routerIP)
            print(routerMAC)
        entryNumber += 1
    
elif args.OS == 'windows': # Either remove this or test it using windows
    commandOutput = out.split('\\r\\n') # command = "arp -a" arp table on Windows ; where do I specify this ?
    routerIP = commandOutput[3].split()[0]
    routerMAC = commandOutput[3].split()