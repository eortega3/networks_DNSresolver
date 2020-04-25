
"""
Authors: Eduardo Ortega & Gretta Von Tobel

Project 03: Iterative DNS Resolver

Project Description:


"""
#IMPORT STATEMENTS
import sys
import socket
from struct import *
import argparse
import random

def argumentParser():
    """
    Parses through arguments to getour IP of interest and our mail exchange boolean value

    Args:
    None

    Returns:
    returns the argument data structure from argParse library
    """
    parser = argparse.ArgumentParser()
    #the mail exchange variable as boolean (T or F)
    parser.add_argument(
                        '-m',
                        help='Mail Exchange look up',
                        action='store_true')
    #the host IP variable to be taken in as a string
    parser.add_argument(
                        'hostIP',
                        help='Host IP',
                        type=str)
    #parse the args and returns values
    arguments = parser.parse_args()
    return arguments

def stringToNetwork(orig_string):
    """
    Converts a standard string to a string that can be sent over
    the network.

    Args:
        orig_string (string): the string to convert

    Returns:
        bytes: The network formatted string (as bytes)

    Example:
        stringToNetwork('www.sandiego.edu.edu') will return
          (3)www(8)sandiego(3)edu(0)
    """
    ls = orig_string.split('.')
    toReturn = b""
    for item in ls:
        formatString = "B"
        formatString += str(len(item))
        formatString += "s"
        toReturn += pack(formatString, len(item), item.encode())
    toReturn += pack("B", 0)
    return toReturn


def networkToString(response, start):
    """
    Converts a network response string into a human readable string.

    Args:
        response (string): the entire network response message
        start (int): the location within the message where the network string
            starts.

    Returns:
        A (string, int) tuple
            - string: The human readable string.
            - int: The index one past the end of the string, i.e. the starting
              index of the value immediately after the string.

    Example:  networkToString('(3)www(8)sandiego(3)edu(0)', 0) would return
              ('www.sandiego.edu', 18)
    """

    toReturn = ""
    position = start
    length = -1
    while True:
        length = unpack("!B", response[position:position+1])[0]
        if length == 0:
            position += 1
            break

        # Handle DNS pointers (!!)
        elif (length & 1 << 7) and (length & 1 << 6):
            b2 = unpack("!B", response[position+1:position+2])[0]
            offset = 0
            """
            TODO: change the following two for loops to the following code

            # strip off leading two bits shift by 8 to account for "length"
            # being the most significant byte
            offset += (length & 1 << i)
            offset += (length & 0x3F) << 8  

            offset += b2
            """
            #original starter code
           
            for i in range(6) :
                offset += (length & 1 << i) << 8
            for i in range(8):
                offset += (b2 & 1 << i)
            
            dereferenced = networkToString(response, offset)[0]
            return toReturn + dereferenced, position + 2

        formatString = str(length) + "s"
        position += 1
        toReturn += unpack(formatString, response[position:position+length])[0].decode()
        toReturn += "."
        position += length
    return toReturn[:-1], position
    

def constructQuery(ID, hostname, qtype):
    """
    Constructs a DNS query message for a given hostname and ID.

    Args:
        ID (int): ID # for the message
        hostname (string): What we're asking for

    Returns: 
        string: "Packed" string containing a valid DNS query message
    """
    flags = 0 # 0 implies basic iterative query

    # one question, no answers for basic query
    num_questions = 1
    num_answers = 0
    num_auth = 0
    num_other = 0

    # "!HHHHHH" means pack 6 Half integers (i.e. 16-bit values) into a single
    # string, with data placed in network order (!)
    header = pack("!HHHHHH", ID, flags, num_questions, num_answers, num_auth,
            num_other)

    qname = stringToNetwork(hostname)
    #qtype = 1 # request A type
    remainder = pack("!HH", qtype, 1)
    query = header + qname + remainder
    return query

#parses through response to get header
def unpackHeader(response):
    """
    Parses through the response

    Args:
        response: response from query in hex format 

    Returns:
        aa(int): the value of the authoratative flag
        authCount(int): the number of authority responses
        addCount(int): the number of the additional responses
        ansCount(int): the number of the answer responses
        rcode(int): the value of the reply code flag
    """
    
    #unpack each part of the header
    transID = unpack('!H', response[0:2])[0]
    flags = unpack('!H', response[2:4])[0]
   
    #qr flag 1 bit
    qrFlag = flags >> 15
    #opcode 4 bits
    opcode = flags & 0x7800
    #aa 1 bit
    aa =((flags & 0x400) !=0)	
    #tc 1 bit
    tc = flags & 0x200
    #rd 1 bit
    rd = flags & 0x100
    #ra 1 bit
    ra = flags & 0x80
    #zero 3 bits allocated to be 0
    #rcode 4 bits
    rcode = flags & 0xF
    
    #unpack number of different answer types 
    qCount = unpack('!H', response[4:6])[0]
    ansCount = unpack('!H', response[6:8])[0]
    authCount = unpack('!H', response[8:10])[0]
    addCount = unpack('!H', response[10:12])[0]
    
    return aa, authCount, addCount, ansCount, rcode

    
def masterUnpack(response, aa, authCount, addCount, ansCount, ipAddress, sock, port, originalHost, rootServers, qtype):
    """
    Unpacks the response fields after header
    
    Args:
        response: response from query in hex format 
        aa: authoratative flag value
        authCount:  number of authoritative responses 
        addCount: number of additional responses
        ansCount: number of answers
        ipAddress: current destination IP address
        sock: sock used to send and receive
        port: port used to send and receive
        originalHost: original hostname typed in by user
        rootServer: list of root servers
        qtype: type of original query
    
    Returns: 
        serverIP(list of strings): list of IP addresses in response 
        
    """
    indexOfQuery = int()
    serverIP = []
    serverNames = []
    indexOfQuery, name, typeQ = unpackQuery(response)
    indexOfQuery, serverIP = unpackAnswers(response, ansCount, indexOfQuery, serverIP, serverNames)
    indexOfQuery, serverNames = unpackAuthorative(response, authCount, indexOfQuery, serverNames, ipAddress, rootServers)
    indexOfQuery, serverIP = unpackAdditional(response, addCount, ansCount, indexOfQuery, serverIP, serverNames, ipAddress, sock, port, originalHost, qtype, rootServers)
    return serverIP

def unpackQuery(response):
    """
        Unpacks the question from the response
    
        Args: 
            response: response from query in hex format
        
        Returns:
            index(int): index where to being next unpack
            name(string): returns name of query
            typeQ(int): type of query
    """     
    #get query name and index
    queryQuestion = networkToString(response, 12)
    name = queryQuestion[0]
    index = queryQuestion[1]
    typeQ = unpack('!H', response[index:index+2])[0]
    index += 4
    return index, name, typeQ

def unpackAnswers(response, ansCount, index, serverIP, serverNames):
    """
        Unpacks the answers from the response
    
        Args: 
            response: response from query in hex format
            ansCount: number of answers 
            index: index of where to next unpack
            serverIP: list of IP addresses from responses 
            serverNames: list of server names from responses 
        
        Returns:
            index(int): index where to being next unpack
            serverIP(list of strings): returns names of server IPs from responses
    """ 
    #iterates through each answer to get IP addresses or returns if none
    if (ansCount == 0): 
        return index, serverIP
    else:
        for ans in range(ansCount):
            nameCheck = networkToString(response, index)
            currDataLength = unpack('!H', response[index+10:index+12])[0]
            theType = unpack('!H', response[index+2:index+4])[0]
            if theType == 1:
                currIP = socket.inet_ntoa(response[index+12:index+12+currDataLength])
                serverIP.append(str(currIP))
            currDataLength += 12
            index += currDataLength
        return index, serverIP

def unpackAuthorative(response, authCount, index, serverNames, ipAddress, rootServer):
    """
        Unpacks the authoratative responses from the response
    
        Args: 
            response: response from query in hex format
            ansCount: number of answers 
            index: index of where to next unpack
            serverNames: list of server names from responses 
            ipAddress: current ipAddress to be used in send and receive
            rootServer: list of root servers
        
        Returns:
            index(int): index where to being next unpack
            serverNames(list of strings): returns names of servers from responses
    """ 
    #iterates through each authorative response and adds server name to list or returns 
    if (authCount == 0): 
        return index, serverNames
    for auth in range(authCount):
        nameCheck = networkToString(response, index)
        currDataLength = unpack('!H', response[index+10:index+12])[0]
        serverName = networkToString(response, index + 12)[0]
        serverNames.append(serverName)
        currDataLength += 12
        index += currDataLength
    return index, serverNames

def unpackAdditional(response, addCount, ansCount, index, serverIP, serverNames, ipAddress, sock, port, originalHost, qtype, rootServers):
    """
        Unpacks the additional responses from the response
    
        Args: 
            response: response from query in hex format
            addCount: number od additional responses
            ansCount: number of answers 
            index: index of where to next unpack
            serverIP: list of IP addresses from responses 
            serverNames: list of server names from responses 
            ipAddress: current destination ip address
            sock: sock to send and receive
            port: port to send and receive
            originalHost: hostname provided by user
            qtype: query type of original query
            rootServers: list of servers

        Returns:
            index(int): index where to being next unpack
            serverIP(list of strings): returns names of server IPs from responses
    """ 
    #if there are no additional responses, go through the server names to contruct new queries and send and receive
    if addCount == 0 :
        for name in serverNames:
            randomID = random.randint(0, 65535)    
            serverList = [ipAddress]
            query = constructQuery(randomID, name, 1)    
            recursiveSendAndRecieve(sock, port, serverList, query, originalHost, rootServers, qtype) 

    #if there are additional records, get those IPs and add to serverIP list  
    for add in range(addCount):
        nameCheck = networkToString(response, index)
        currDataLength = unpack('!H', response[index+10:index+12])[0]
        if currDataLength == 4:
            currIP = socket.inet_ntoa(response[index + 12 :index + 12 + currDataLength])
            serverIP.append(str(currIP))
        currDataLength += 12
        index += currDataLength
    return index, serverIP       

def getIP(response, aa, authCount, addCount, ansCount, ipAddress, sock, port, originalHost, rootServers, qtype):
    """
        Gets the IP address with different cases for different types

        Args: 
            response: response from query in hex format
            aa: authoratative flag value
            authCount: number of authoratative responses
            addCount: number of additional responses
            ansCount: number of answer responses
            index: index of where to next unpack
            ipAddress: current destination ip address
            sock: sock to send and receive
            port: port to send and receive
            originalHost: hostname provided by user
            rootServers: list of servers 
            qtype: query type of original query

        
        Returns:
            authIP(string): IP address
    """ 
    #get type of answer
    index = networkToString(response, 12)[1] + 4
    nameIndex = networkToString(response, index)[1]
    currType = unpack('!H', response[nameIndex:nameIndex+2])[0]
    
    #type A: returns IP address 
    if currType == 1: 
        currDataLength = unpack('!H', response[index+10:index+12])[0]
        authIP = socket.inet_ntoa(response[index+12:index+12+currDataLength])
    
    #type CNAME: constructs to query for cname or returns ip address
    elif currType == 5:
        if ansCount == 1:
            currDataLength = unpack('!H', response[index+10:index+12])[0]
            index = index + 12
            checkCname = networkToString(response, index)[0]
            newQueryToBeCalled = constructQuery(random.randint(0,65535), checkCname, 1)
            recursiveSendAndRecieve(sock, 53, rootServers,newQueryToBeCalled, checkCname, rootServers, 1)
        else:
            currDataLength = unpack('!H', response[index+10:index+12])[0]
            index = index + 12 + currDataLength
            currDataLength = unpack('!H', response[index+10:index+12])[0]
            authIP = socket.inet_ntoa(response[index+12:index+12+currDataLength])
    
    #type MX: runs masterUnpack again to go through response
    elif currType == 15:
        authIP = masterUnpack(response, aa, authCount, addCount, ansCount, ipAddress, sock, port, originalHost, rootServers, qtype)
        print(authIP)

    #type SOA: returns error message that the IP address is not valuid
    elif currType == 6:
        print("Sorry, this is not a vaild request")
        authIP = "SOA"
        sys.exit(1)
    
    return authIP

def getMailServer(response, sock, port, rootServers, originalHost):
    """
        goes through MX servers in response
    
        Args: 
            response: response from query in hex format
            sock: sock to send and receive
            port: port to send and receive
            rootServers: list of servers
            originalHost: hostname provided by user
    """   
    aa, authCount, addCount, ansCount, rcode =  unpackHeader(response)
    index, name, typeQ = unpackQuery(response)
    mailServers = []
    if ansCount == 0:
        print("\nSorry, this is not a vaild request\n")
        sys.exit(1)
    #iterates through mail servers in answer and add them to mailServers list 
    for i in range(ansCount):
        type = unpack('!H', response[index+2:index+4])[0]
        #if CNAME: constructs new queries to recursively send and receive again
        if type == 5:
            currDataLength = unpack('!H', response[index+10:index+12])[0]
            index = index + 12
            checkCname = networkToString(response, index)[0]
            newQueryToBeCalled = constructQuery(random.randint(0,65535), checkCname, 15)
            recursiveSendAndRecieve(sock, 53, rootServers,newQueryToBeCalled, checkCname, rootServers, 15)
        mxName = networkToString(response, index+14)[0]
        currDataLength = unpack('!H', response[index+10:index+12])[0]
        currDataLength += 12
        index += currDataLength
        mailServers.append(mxName)
    for server in mailServers:
        mailQuery = constructQuery(random.randint(0,65535), server, 1)
        recursiveSendAndRecieve(sock, port, rootServers, mailQuery, server, rootServers, 1)
    
def unpackAA(response, aa, authCount, addCount, ansCount, ipAddress, sock, port, originalHost, rootServers, qtype, name):
    """
        Goes into the authoratative response to get the correct IP address we need
    
        Args: 
            response: response from query in hex format
            aa: value for authoratative flag
            authCount: number of authority responses
            addCount: number of additional responses
            ansCount: number of answer responses
            ipAddress: current ip address
            sock: sock to send and receive
            port: port to send and receive
            originalHost: hostname provided by user
            rootServers: list of servers
            qtype: query type of original query
            name: name of current query 

        Returns:
            string: Ip address

    """ 
    #if the current query is the same as the original query name, get the IP address
    if name == originalHost: 
        #type A
        if qtype == 1:
            authIP = getIP(response, aa, authCount, addCount, ansCount, ipAddress, sock, port, originalHost, rootServers, qtype)
            return authIP
        #type MX
        elif qtype == 15:
            authIP = getIP(response, aa, authCount, addCount, ansCount, ipAddress, sock, port, originalHost, rootServers, qtype)
            if (authIP == "SOA"):
                return authIP
            else:
                return authIP[0]
    #if not get IP of authorative then construct new query for mail servers
    else:
        authIP = getIP(response, aa, authCount, addCount, ansCount, ipAddress, sock, port, originalHost, rootServers, qtype)
        if authIP == "SOA":
            return authIP
        else:
            newQuery = constructQuery(random.randint(0,65535), originalHost, qtype)
            sock.sendto(newQuery, (authIP, port))
            newResponse = sock.recv(4096)
            if qtype == 1:
                rightIP = getIP(newResponse, aa, authCount, addCount, ansCount, ipAddress, sock, port, originalHost, rootServers, qtype)
            elif qtype == 15:
                rightIP = getMailServer(newResponse, sock, port, rootServers, originalHost)
            return rightIP 
    
def recursiveSendAndRecieve(sock, port, serverList, query, originalHost, rootServers, qtype):
    """
        Recursive function to send and receive queries to iterative get to authorative server
    
        Args: 
            sock: sock to send and receive
            port: port to send and receive
            query: the query to send
            originalHost: hostname provided by user
            rootServers: list of servers
            qtype: query type of original query
    """ 
    for ipAddress in serverList:
        print("Trying IP: " + ipAddress)
        try:
            #sendthe message to hostIP
            sock.sendto(query, (ipAddress, port))
            response = sock.recv(4096)
            
            #unpack header and query to get query name, flags, and response info
            aa, authCount, addCount, ansCount, rcode =  unpackHeader(response)
            index, name, typeQ = unpackQuery(response)
            
            if typeQ == 1:
                currType = "A"
            if typeQ == 15:
                currType = "MX"
            print("Query name: " + name + "     Query Type: " + currType)
            print("Answer Count: " + str(addCount) + "  Authoritative Count: " + str(ansCount) + "  Answer Count: " + str(ansCount) + "\n")
            #if the reply code is 5, the connection is refused
            if(rcode == 5):
                print("\nYou have recieved a refused response. The IP address cannot be obtained.\n")
                sys.exit(1)

            #if the aa flag is true, get IP or check for MX 
            if (aa) :
                authIP = unpackAA(response, aa, authCount, addCount, ansCount, ipAddress, sock, port, originalHost, rootServers, qtype, name)
                if authIP == "SOA":
                    continue
                else:
                    if qtype == 1: 
                        print("\nThe name " + originalHost + " resolves to: " + str(authIP)+ "\n")
                        sys.exit(1)
                    elif qtype == 15: 
                        print("\nThe mail exchange for " + originalHost + " resolves to: " + str(authIP) + "\n")
                        sys.exit(1)
            
            #if no aa flag, get new servers from master unpack and run send and recieve for the next set of servers          
            else:
                serverIP = masterUnpack(response, aa, authCount, addCount, ansCount, ipAddress, sock, port, originalHost, rootServers, qtype)
                recursiveSendAndRecieve(sock, port, serverIP, query, originalHost, rootServers, qtype)
            
        except socket.timeout as e:
            print("Exception:", e)

def main(argv=None):
    if argv is None:
        argv = sys.argv
    args = argumentParser()
    
    print("\nWe will look for the IP for: "   + args.hostIP)
    print("Boolean for mail lookup: " + str(args.m) + "\n")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)   # socket should timeout after 5 seconds
    
    #transaction field is 16 bits in length so the range of values is from 0
    #to 65,535
    randomID = random.randint(0, 65535)

    if args.m:  qtype = 15
    else:       qtype = 1

    #construct query
    query = constructQuery(randomID , args.hostIP, qtype)

    #gets all possible servers from root-servers.txt
    servers = []
    with open('root-servers.txt', 'r') as aFile: 
        for line in aFile:
            strippedLine = line.strip()
            servers.append(strippedLine)

    print('List of the root servers are below')
    print(servers)
    print("\n")

    #loop function to go through Root IP lists and check their respective TLD
    #and their respective Authorative servers
    recursiveSendAndRecieve(sock, 53, servers, query, args.hostIP, servers, qtype)

if __name__ == "__main__":
    sys.exit(main())
