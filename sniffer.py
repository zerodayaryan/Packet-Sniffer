import scapy.all as scapy
import json
import argparse

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","-interface", dest = "interface", help = "Enter the interface name")
    parser.add_argument("-c","-count", dest = "count",type = int, help="Enter how many packets to capture. 0 represents infinite packets")
    options = parser.parse_args()
    if not options.interface or not options.count:
        parser.error("[-] Please enter valid interface")
        
    return options.interface, options.count
    
def capPackets(interface, count):
    packets={}
    pkts = scapy.sniff(count = count, iface = interface)
    for i in range(len(pkts)):
        if "IP" in pkts[i]:
            prtcl = pkts[i]["IP"].proto
            srcIP=pkts[i]["IP"].src
            destIP=pkts[i]["IP"].dst
            size = pkts[i]["IP"].len
            packets[i]={"type": "IP","srcIp":srcIP, "destIP":destIP, "payload size": size, "protocol": prtcl}
        elif "IPv6" in pkts[i]:
            srcIP=pkts[i]["IPv6"].src
            destIP=pkts[i]["IPv6"].dst
            size = pkts[i]["IPv6"].plen
            prtcl = pkts[i]["IPv6"].nh
            packets[i]={"type": "IPv6", "srcIp":srcIP, "destIP":destIP, "payload size": size, "protocol": prtcl}
    with open("output.json", "w") as json_file:
        json.dump(packets, json_file, indent=4)
    print(packets)
    

interface, count = get_args()
cap = capPackets(interface, count)
