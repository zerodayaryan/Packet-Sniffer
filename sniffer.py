import argparse
import json
import scapy.all as scapy

def get_args():  # argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "-interface",
        type=str,
        dest="interface",
        help="Enter the interface name",
        required=True,
    )
    parser.add_argument(
        "-c",
        "-count",
        dest="count",
        type=int,
        help="Enter how many packets to capture. 0 represents infinite packets. Default value is  5",
        default=5,
    )
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please enter valid interface")

    return options.interface, options.count


def capPackets(interface, count):  # function to capture packets
    packets = {}
    pkts = scapy.sniff(count=count, iface=interface)
    for i in range(len(pkts)):
        if "IP" in pkts[i]:
            parseIP(pkts, i, packets)
        elif "IPv6" in pkts[i]:
            parseIP6(pkts, i, packets)
        storePacket(packets)


def parseIP(pkts, i, packets):  # Function to parse IPv4 packets
    packets[i] = {
        "type": "IP",
        "srcIp": pkts[i]["IP"].src,
        "destIP": pkts[i]["IP"].dst,
        "payload size": pkts[i]["IP"].len,
    }
    if "UDP" in pkts[i]:
        packets[i].update(udpPkt(pkts, i))
    elif "TCP" in pkts[i]:
        packets[i].update(tcpPkt(pkts, i))


def parseIP6(pkts, i, packets):  # Function to parse IPV6 packets
    packets[i] = {
        "type": "IPv6",
        "srcIp": pkts[i]["IPv6"].src,
        "destIP": pkts[i]["IPv6"].dst,
        "payload size": pkts[i]["IPv6"].plen,
    }
    if "UDP" in pkts[i]:
        packets[i].update(udpPkt(pkts, i))
    elif "TCP" in pkts[i]:
        packets[i].update(tcpPkt(pkts, i))
    return packets


def udpPkt(pkts, i):
    UDP = {
        "Protocol": "UDP",
        "Src": pkts[i]["UDP"].sport,
        "Dst": pkts[i]["UDP"].dport,
        "len": pkts[i]["UDP"].len,
    }
    return UDP


def tcpPkt(pkts, i):
    tcp = {
        "Protocol": "TCP",
        "Src": pkts[i]["TCP"].sport,
        "Dst": pkts[i]["TCP"].dport,
        "Ack": pkts[i]["TCP"].ack,
    }
    return tcp


def storePacket(packet):  # function to store parsed packets in json format
    with open("output.json", "w") as json_file:
        json.dump(packet, json_file, indent=4)
        print(packet)


interface, count = get_args()
cap = capPackets(interface, count)
