#Use scapy to capture and parse packets on your own network interface. Log source/destination IPs, protocols, and payload sizes. 
# Good next step: build a simple dashboard (matplotlib or a live terminal UI) showing traffic by protocol.
import scapy.all as scapy

def capPackets():
    packets={}
    pkts = scapy.sniff(count = 5, iface="en0")
    prtcl = 0
    for i in range(5):
        if "IP" in pkts[i]:
            srcIP=pkts[i]["IP"].src
            destIP=pkts[i]["IP"].dst
            size = pkts[i]["IP"].len
            if pkts[i]["IP"].proto == 6:
                prtcl = "TCP"
            elif pkts[i]["IP"].proto == 17:
                prtcl = "UDP"
            elif pkts[i]["IP"].proto == 1:
                prtcl = "ICMP"
            else:
                prtcl = "Other Protocol"
            packets[pkts[i]["IP"].id]={"srcIp":srcIP, "destIP":destIP, "payload size": size, "protocol": prtcl}
        else:
            print("Not an IP packet")
    print(packets)

capPackets()
