#Use scapy to capture and parse packets on your own network interface. Log source/destination IPs, protocols, and payload sizes. 
# Good next step: build a simple dashboard (matplotlib or a live terminal UI) showing traffic by protocol.
import scapy.all as scapy
import json

def capPackets():
    packets={}
    pkts = scapy.sniff(count = 5)
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
    

capPackets()
