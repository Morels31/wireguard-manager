#!/bin/python3

from requests import get
import subprocess
import ipaddress
import glob
import sys
import os
import re



serverConfigUnformatted = """
[Peer]
# {username}
PublicKey = {clientPubKey}
AllowedIPs = {serverAllowedIPs}
"""

clientConfigUnformatted = """
[Interface]
# {username}-{configN}
PrivateKey = {clientPrivKey}
Address = {address}

[Peer]
PublicKey = {serverPubKey}
AllowedIPs = {clientAllowedIPs}
Endpoint = {serverEndpoint}:{serverPort}
"""


ipRegex = re.compile("(\d+\.\d+\.\d+\.\d+)(\/\d+)?")
addrRegex = re.compile("^Address\s*=", re.IGNORECASE)
privKeyRegex = re.compile("^PrivateKey\s*=\s*([A-Za-z0-9+/]{43}=)", re.IGNORECASE)
listenPortRegex = re.compile("^ListenPort\s*=\s*([0-9]+)", re.IGNORECASE)
allowedIPsRegex = re.compile("^AllowedIPs\s*=", re.IGNORECASE)



#Prints the error string taken in input and terminates the script.

def errorr(s):
    print("ERROR: "+str(s)+". Exiting...")
    sys.exit(1)



#Gets in input a string that will be printed,
#and an array of strings (choices).
#Returns the chosen one. (default is 0)

def choice(askStr, options):
    l = len(options)
    while True:
        print(askStr)
        for i in range(l):
            print("\t"+str(i)+") "+options[i])

        x = input("\nEnter a number (default is 0): ")

        if(len(x)==0):
            return 0
        if(x.isnumeric()):
            x = int(x)
            if(x>=0 and x<l):
                return x

        print("\nInvalid choice, retry")



#Gets in input a wireguard configuration filename, and parses it.
#Returns an array of IPv4Network objects (taken from the 'Address' line of the config),
#a set of IPv4Address, each of them is an already used ip (taken from the 'AllowedIPs' lines)
#the server private key, later needed to derive the public key to put in the new configs.
#and the server listening port.

def parseConfigurationFile(filename):
    try:
        f = open(filename, "r")
    except:
        errorr("Failed opening file: '"+filename+"' in reading mode")

    networksArr = []
    #using a set for removing eventual duplicates and because lookups are faster.
    alreadyUsedIPs = set()
    serverPrivKey = None
    serverPort = None

    for line in f:
        if addrRegex.match(line):
            addrs = ipRegex.findall(line)
            for addr in addrs:
                #here each 'addr' variable is a tuple like this ('10.0.0.1','/24')
                if(len(addr[1])==0):
                    print("WARNING: '[Interface]' 'Address' line does not contain network mask, implicitly setting it to /24.")
                    network = ipaddress.ip_network(addr[0]+"/24", strict=False)
                else:
                    network = ipaddress.ip_network(addr[0]+addr[1], strict=False)

                networksArr.append(network)
                alreadyUsedIPs.add(ipaddress.ip_address(addr[0]))
                #adding invalid ips to alreadyUsedIPs set, so that will not be used.
                alreadyUsedIPs.add(network.network_address)
                alreadyUsedIPs.add(network.broadcast_address)

        elif allowedIPsRegex.match(line):
            addrs = ipRegex.findall(line)
            for addr in addrs:
                for ip in ipaddress.ip_network(addr[0]+addr[1], strict=False).hosts():
                    alreadyUsedIPs.add(ip)

        else:
            if(serverPort==None):
                matchRes = listenPortRegex.match(line)
                if(matchRes!=None):
                    serverPort = matchRes[1]
                    
            if(serverPrivKey==None):
                matchRes = privKeyRegex.match(line)
                if(matchRes!=None):
                    serverPrivKey = matchRes[1]
    f.close()

    if(serverPort==None):
        errorr("The configuration file given in input is not a wireguard server")

    if(serverPrivKey==None):
        errorr("The configuration parser didn't find the server private key")

    return networksArr, alreadyUsedIPs, serverPrivKey, serverPort



#Gets in input an array of IPv4Network objects (valid networks),
#a set of already used IPv4Address objects, and an integer 'nIPs'.
#Returns an array of IPv4Address objects, that will contain
#the first 'nIPs' available IPs.

def findFirstNAvailableIPs(networksArr, alreadyUsedIPs, nIPs):
    IPs = []
    n = 0
    for network in networksArr:
        for ip in network:
            if ip not in alreadyUsedIPs:
                IPs.append(ip)
                n += 1
                if(n>=nIPs):
                    return IPs
    errorr("Not enough IPs available")



#Gets in input an array of IPv4Network objects (valid networks),
#a set of already used IPv4Address objects, and an integer 'nIPs'.
#Returns an array of IPv4Address objects, that will contain
#the first 'nIPs' contiguous available IPs.

def findFirstNContiguousAvailableIPs(networksArr, alreadyUsedIPs, nIPs):
    for network in networksArr:
        n = 0
        a = b = network.network_address
        while(b < network.broadcast_address):
            if b not in alreadyUsedIPs:
                n += 1
                b += 1
            else:
                n = 0
                a = b = b + 1
            if(n>=nIPs):
                #Returns the IPs between a and b (excluded)
                return [ ipaddress.ip_address(i) for i in range(int(a), int(b)) ]
    errorr("Not enough IPs available")



#Gets in input an array of IPv4Network objects (valid networks), and an ip.
#Returns whether th ip is inside one of the networks or not.

def isIPInsideValidNetworks(ip, networksArr):
    for network in networksArr:
        if ip in network:
            return True
    return False







##########################################################################################################

def getIPFromUser(askStr):
    while True:
        ip = input(askStr)
        if(len(ip)==0):
            return None
        try:
            return ipaddress.ip_address(ip)
        except:
            print("\nInvalid input. Retry...")

##########################################################################################################

 
def getNetworkFromUser(askStr):
    while True:
        network = input(askStr)
        if(len(network)==0):
            return None
        try:
            return ipaddress.ip_network(network, strict=False)
        except:
            print("\nInvalid input. Retry...")
                   








#Gets in input an array of IPv4Network objects (valid networks),
#a set of already used IPv4Address objects, and an integer 'nIPs'.
#Asks the user to enter 'nIPs' valid IPs, that will be returned as
#an array of IPv4Address objects

def getIPsFromUser(networksArr, alreadyUsedIPs, nIPs):
    IPs = []
    for i in range(nIPs):
        while True:
            ip = getIPFromUser("\nEnter the IP n°"+str(i)+": ")

            if(ip==None):
                continue
            if ip in alreadyUsedIPs:
                print("\nIP already in use. Retry...")
                continue
            if isIPInsideValidNetworks(ip, networksArr):
                alreadyUsedIPs.add(ip)
                IPs.append(ip)
                break
            print("\nIP is outside of valid subnets. Retry...")

    return IPs



#Calls the program "wg genkey" to generate a new private key.
#Returns the generated private key.

def newPrivKey():
    try:
        result = subprocess.run(["wg","genkey"], capture_output=True)
        return result.stdout.decode().replace("\n","")
    except FileNotFoundError:
        errorr("Wireguard not installed")



#Gets in input a private key and pipes it to the stdin of the program "wg pubkey".
#Returns the derived public key.

def fromPrivToPubKey(privkey):
    try:
        result = subprocess.run(["wg","pubkey"], input=privkey.encode(), capture_output=True)
        return result.stdout.decode().replace("\n","")
    except FileNotFoundError:
        errorr("Wireguard not installed")



#Gets in input a private or public key.
#Returns if the key is valid or not.

def isKeyValid(key):
    keyRegex = re.compile("^[A-Za-z0-9+/]{43}=$")
    return keyRegex.match(key) != None



#Asks the user to manually enter a valid private or public key.
#Returns the key taken in input.

def readKeyFromUser():
    while True:
        key = input("\nManually enter a valid key: ")
        if isKeyValid(key):
            return key
        print("\nInvalid key. Retry...")



#Returns the public IP of the machine, or None if something failed.

def getPublicIP():
    publicIP = get('https://api.ipify.org').content.decode('utf8')
    if ipRegex.match(publicIP):
        return publicIP
    return None



def main():
    if(len(sys.argv)<=1):
        confFiles = glob.glob("/etc/wireguard/*.conf")
        confFiles += glob.glob("./*.conf")
        if(len(confFiles)==0):
            print("No .conf files found in the wireguard directory or the current.")
            print("Either go to a directory that has at least one, or enter a filepath as input parameter.")
            sys.exit(1)
        selection = choice("\nChoose the .conf file to work on:", confFiles)
        filename = confFiles[selection]
    else:
        filename = sys.argv[1]


    networksArr, alreadyUsedIPs, serverPrivKey, serverPort = parseConfigurationFile(filename)

    serverPubKey = fromPrivToPubKey(serverPrivKey)


    while True:
        username = input("\nEnter a username: ")
        if(len(username)>0):
            break
        print("\nInvalid choice, retry")

    
    n = choice("\nHow should client private/public key pair be assigned?",[
        "Automatically generate a new pair.",
        "I will manually enter a private key, and the public one should be derived from it.",
        "I will manually enter a public key, and later manually add the private one to config files."])
    match n:
        case 0:
            clientPrivKey = newPrivKey()
            clientPubKey = fromPrivToPubKey(clientPrivKey)
        case 1:
            clientPrivKey = readKeyFromUser()
            clientPubKey = fromPrivToPubKey(clientPrivKey)
        case 2:
            clientPrivKey = "TO_BE_REPLACED_WITH_PRIVATE_KEY"
            clientPubKey = readKeyFromUser()

#    print("\nPrivate key: "+str(clientPrivKey))
#    print("Public key: "+clientPubKey)


    while True:
        nIPs = input("\nHow many different clients do you need?: ")
        if(nIPs.isnumeric()):
            nIPs = int(nIPs)
            break
        print("\nInvalid choice, retry")


    n = choice("\nHow should IPs be assigned?",[
        "Automatically pick the first "+str(nIPs)+" available.",
        "Automatically pick the first contiguous "+str(nIPs)+" available.",
        "I will manually set them."])
    match n:
        case 0:
            IPs = findFirstNAvailableIPs(networksArr, alreadyUsedIPs, nIPs)
        case 1:
            IPs = findFirstNContiguousAvailableIPs(networksArr, alreadyUsedIPs, nIPs)
        case 2:
            IPs = getIPsFromUser(networksArr, alreadyUsedIPs, nIPs)
    
    print("\nThis IPs will be assigned to your public key:")
    for ip in IPs:
        print("\t"+str(ip))


    serverAllowedIPs = ""
    for i in range(len(IPs)):
        if(i>0):
            serverAllowedIPs += ", "
        serverAllowedIPs += str(IPs[i])

    serverConfig = serverConfigUnformatted.format(
        username = username,
        clientPubKey = clientPubKey,
        serverAllowedIPs = serverAllowedIPs)

        

    serverEndpoint = getPublicIP()
    if(serverEndpoint!=None):
        n = choice("\nHow the server IP/hostname should be assigned?",[
            "Automatically set it to the public IP of the machine ("+serverEndpoint+").",
            "I will manually enter the IP/hostname."])
        if(n==1):
            serverEndpoint = getIPFromUser("\nEnter the IP/hostname: ")
    else:
        serverEndpoint = getIPFromUser("\nEnter the IP/hostname: ")


    n = choice("\nHow should the server port should be assigned?",[
        "Automatically set it to the one specified in the server config ("+serverPort+").",
        "I will manually enter the server port."])

    if(n==1):
        while True:
            serverPort = input("\nEnter the server port: ")
            if(serverPort.isnumeric() and int(serverPort) < 2**16):
                break
            print("\nInvalid input. Retry...")

#   print("Server endpoint = "+serverEndpoint+":"+serverPort


    n = choice("\nWhich IP addresses should be routed via wireguard when client is enabled?",[
        "Route everything (0.0.0.0/0).",
        "I will manually enter the subnet(s) of IPs to be routed via wireguard."])

    clientAllowedIPs = ""
    while True:
        network = getNetworkFromUser("\nEnter a subnet (CIDR notation): ")
        if(network!=None):
            clientAllowedIPs += str(network)
            break
    while True:
        network = getNetworkFromUser("\nEnter a subnet (CIDR notation) (or press ENTER to continue): ")
        if(network==None):
            break
        clientAllowedIPs += ", "+str(network)


    clientConfigsArr = []
    for i in range(nIPs):
        clientConfigsArr.append( clientConfigUnformatted.format(
            username = username,
            configN = i,
            clientPrivKey = clientPrivKey,
            address = IPs[i],
            serverPubKey = serverPubKey,
            clientAllowedIPs = clientAllowedIPs,
            serverEndpoint = serverEndpoint,
            serverPort = serverPort))


    print("- - -  Server config  - - -\n")
    print(serverConfig)
    print("\n- - - - - - - - - - - - - -\n\n")

    for i in range(len(clientConfigsArr)):
        print("- - - Client config "+str(i)+" - - -\n")
        print(clientConfigsArr[i])
    print("\n- - - - - - - - - - - - - -")



    # TODO

    # New TOML parser, that divides the config in sections ([Interface], [Peer])
    # Better than the python one (tomllib) because it works with multiple sections with the same name
    # Creating a array of dictionaries es: [ { Text: "[Peer]\n ...", AllowedIPs:"asd", ... }, {...}  ]
    # This could allow to not only add configs, but edit or delete them.

    # Warn the user if the /etc/wireguard directory is not readable (needs root).

    # Final touches


if __name__ == '__main__':
    main()
