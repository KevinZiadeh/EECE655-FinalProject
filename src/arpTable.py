import subprocess
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("OS", type=str, help="OS you are currently using the script on (i.e. 'linux' for Linux and 'windows' for Windows")
args = parser.parse_args()

if args.OS == 'linux':
    commandOutput = str(subprocess.check_output("ip neigh", shell=True, stderr=subprocess.STDOUT)).split('\\n')
    routerIP = commandOutput[0].split()[0][2:]
    routerMAC = commandOutput[0].split()[4]
    print(routerIP)
    print(routerMAC)
elif args.OS == 'windows': # Either remove this or test it using windows
    commandOutput = out.split('\\r\\n') # command = "arp -a" arp table on Windows ; where do I specify this ?
    routerIP = commandOutput[3].split()[0]
    routerMAC = commandOutput[3].split()