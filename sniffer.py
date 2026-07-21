import argparse
import json
import scapy.all as scapy
import threading

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
    pkts = scapy.sniff(count=count, iface=interface, prn=parsePkt)

def parsePkt(pkts):
    packets = {}
    if "IP" in pkts:
        parseIP(pkts, packets)
        print(packets, flush=True)
        return packets
    elif "IPv6" in pkts:
        parseIP6(pkts, packets)
        print(packets, flush=True)
        return packets

    # storePacket(packets)
    
def parseIP(pkts, packets):  # Function to parse IPv4 packets
    packets.update({
        "type": "IP",
        "srcIp": pkts["IP"].src,
        "destIP": pkts["IP"].dst,
        "payload size": pkts["IP"].len,
    })
    if "UDP" in pkts:
        packets.update(udpPkt(pkts))
    elif "TCP" in pkts:
        packets.update(tcpPkt(pkts))
    elif "ICMP" in pkts:
        packets.update(icmpPkt(pkts))

def parseIP6(pkts, packets):  # Function to parse IPV6 packets
    packets.update({
        "type": "IPv6",
        "srcIp": pkts["IPv6"].src,
        "destIP": pkts["IPv6"].dst,
        "payload size": pkts["IPv6"].plen,
    })
    if "UDP" in pkts:
        packets.update(udpPkt(pkts))
    elif "TCP" in pkts:
        packets.update(tcpPkt(pkts))
    elif "ICMP" in pkts:
        packets.update(icmpPkt(pkts))
    return packets


def udpPkt(pkts):
    UDP = {
        "Protocol": "UDP",
        "Src": pkts["UDP"].sport,
        "Dst": pkts["UDP"].dport,
        "len": pkts["UDP"].len,
    }
    return UDP


def tcpPkt(pkts):
    tcp = {
        "Protocol": "TCP",
        "Src": pkts["TCP"].sport,
        "Dst": pkts["TCP"].dport,
        "Ack": pkts["TCP"].ack,
    }
    return tcp

def icmpPkt(pkts):
    if pkts["ICMP"].type == 0 or pkts["ICMP"].type == 8:
        icmp = {
            "Protocol":"ICMP - Query message",
            "Type":pkts["ICMP"].type,
            "ID":pkts["ICMP"].id,
            "Sequence":pkts["ICMP"].seq,
            "Payload":pkts["ICMP"].length
        }
        return icmp
    elif pkts["ICMP"].type == 3 or pkts["ICMP"].type == 5 or pkts["ICMP"].type == 11 or pkts["ICMP"].type == 12:
        icmp={
            "Protocol":"ICMP - Error message",
            "Type":pkts["ICMP"].type,
            "Code":pkts["ICMP"].code
        }
        return icmp
    elif pkts["ICMP"].type == 13 or pkts["ICMP"].type == 14:
        icmp = {
            "Protocol":"ICMP - Query message",
            "Type":pkts["ICMP"].type,
            "Code":pkts["ICMP"].code,
            "ID":pkts["ICMP"].id,
            "Sequence":pkts["ICMP"].seq,
            "Origin timestamp":pkts["ICMP"].ts_ori,
            "Recieve timestamp":pkts["ICMP"].ts_rx,
            "Transmit timestamp":pkts["ICMP"].ts_tx,
        }
        return icmp
    else:
        icmp={
            "Protocol":"ICMP - Other/Unknown",
            "Type":pkts["ICMP"].type
        }
        return icmp

        
# def storePacket(packet):  # function to store parsed packets in json format
#     with open("output.json", "w") as json_file:
#         json.dump(packet, json_file, indent=4)
#         print(packet)


interface, count = get_args()
capPackets(interface, count)
