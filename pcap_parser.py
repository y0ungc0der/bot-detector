# -*- coding: utf-8 -*- 
import pyshark
import datetime
import ipaddress
from sys import argv

# Getting a list of bot hosts
def BotDetect(timeReferences):

    botList = {}   # list of bot hosts
    i = 0   # counter of bot hosts
    
    for host in timeReferences:
        # If the number of DNS requests from this host does not exceed the norm thengo to next host
        numOfPackets = len(timeReferences[host])        
        if (numOfPackets < 10):
            continue 

        numOfShInt = 0  # counter of requests
        averTimeDiff = 0   # average value of the time difference

        # Calculation of the average value of the time difference between sending requests
        for i in range(numOfPackets - 1):
            averTimeDiff += (timeReferences[host][i + 1] - timeReferences[host][i]).seconds
        averTimeDiff = averTimeDiff / numOfPackets

        # Calculation of the counter of nearby requests with a 'short' time between sending 
        for i in range(numOfPackets - 1):
            timeDiff = (timeReferences[host][i + 1] - timeReferences[host][i]).seconds
            if (timeDiff > (averTimeDiff - 60)) and (timeDiff < (averTimeDiff + 60)):
               numOfShInt += 1

        # If the number of closest DNS requests from this host is high then add the host's ip address to the list of bots
        if (numOfShInt > (numOfPackets * 0.9)):
            botList [i] = host
            i += 1
            
    return botList

# Getting a list of time referencesList for hosts
def GetTimeReferencesList(pcap):

    timeReferences = {} # list of time referencesList
    subnet = ipaddress.ip_network('192.168.50.0/24')    # list of IPv4 addresses in subnet 192.168.50.0
    
    for packet in pcap:
    
        # Getting the ip address of the host that made the DNS request
        ip = packet.ip.src
        
        for i in range(10, 35):
            # If the  ip address is on the subnet LVS 1
            if (ip == str(ipaddress.IPv4Address(subnet[i]))):
            
                # The time the packet was captured
                time = packet.sniff_time
                
                # Update data in list or supplement them                
                if ip not in timeReferences:
                    timeReferences.update({ip : []})
                    
                # Append multiple values for one key in list
                timeReferences[ip].append(time)
                
    return timeReferences

def main(argv):

    if len(argv) < 2:
        print("Type: script.py *.pcap")
        return

    # Import packets from a saved capture file with filters
    pcap = pyshark.FileCapture(argv[1], display_filter = "dns and ip.src != 192.168.50.88")
    
    # Getting list of ip:time references
    timeReferences = GetTimeReferencesList(pcap)
    
    # Getting list of bot host
    botHostList = BotDetect(timeReferences)
    
    for host in botHostList:
        print (botHostList[host], 'is a bot')
    
    return  

if __name__ == '__main__':
    main(argv) 
