##Lots of work to do ;)
## fix packet storing in json file
## netwok instrution detection system
import argparse
import scapy.all as scapy
from rich.live import Live
from rich.table import Table  
from rich.console import Console
import json

console = Console()

def buildTable():
    table = Table(title="Live Packet Capture")
    table.add_column("Type")
    table.add_column("Src IP")
    table.add_column("Dst IP")
    table.add_column("Protocol")
    table.add_column("Details")
    return table

packet_table = buildTable()

def parsePkt(pkts):
    packets = {}
    if "IP" in pkts:
        parseIP(pkts, packets)
    elif "IPv6" in pkts:
        parseIP6(pkts, packets)
    else:
        return
    

    packet_table.add_row(
        packets.get("type", ""),
        str(packets.get("srcIp", "")),
        str(packets.get("destIP", "")),
        packets.get("Protocol", ""),
        str({k: v for k, v in packets.items() if k not in ("type", "srcIp", "destIP", "Protocol")})
    )
    return packets

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i", "--interface",
        type=str,
        dest="interface",
        help="Enter the interface name",
        required=True,
    )
    parser.add_argument(
        "-c", "--count",
        dest="count",
        type=int,
        help="Enter how many packets to capture. 0 represents infinite packets. Default value is 5",
        default=5,
    )
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please enter valid interface")
    return options.interface, options.count

def capPackets(interface, count):
    with Live(packet_table, console=console, refresh_per_second=4):
        scapy.sniff(count=count, iface=interface, prn=parsePkt)



def parseIP(pkts, packets):
    srcPkt = pkts["IP"].src
    dstPkt = pkts["IP"].dst
    packets.update({
        "type": "IP",
        "srcIp": srcPkt,
        "destIP": dstPkt,
        "payload size": pkts["IP"].len,
    })
    if "UDP" in pkts:
        packets.update(udpPkt(pkts))
    elif "TCP" in pkts:
        packets.update(tcpPkt(pkts))
    elif "ICMP" in pkts:
        packets.update(icmpPkt(pkts))
    return packets


def parseIP6(pkts, packets):
    srcPkt = pkts["IPv6"].src
    dstPkt = pkts["IPv6"].dst
    packets.update({
        "type": "IPv6",
        "srcIp": srcPkt,
        "destIP": dstPkt,
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
    return {
        "Protocol": "UDP",
        "Src": pkts["UDP"].sport,
        "Dst": pkts["UDP"].dport,
        "len": pkts["UDP"].len,
    }


def tcpPkt(pkts):
    return {
        "Protocol": "TCP",
        "Src": pkts["TCP"].sport,
        "Dst": pkts["TCP"].dport,
        "Ack": pkts["TCP"].ack,
    }


def icmpPkt(pkts):
    icmp_type = pkts["ICMP"].type
    if icmp_type in (0, 8):
        return {
            "Protocol": "ICMP - Query message",
            "Type": icmp_type,
            "ID": pkts["ICMP"].id,
            "Sequence": pkts["ICMP"].seq,
            "Payload": pkts["ICMP"].length,
        }
    elif icmp_type in (3, 5, 11, 12):
        return {
            "Protocol": "ICMP - Error message",
            "Type": icmp_type,
            "Code": pkts["ICMP"].code,
        }
    elif icmp_type in (13, 14):
        return {
            "Protocol": "ICMP - Query message",
            "Type": icmp_type,
            "Code": pkts["ICMP"].code,
            "ID": pkts["ICMP"].id,
            "Sequence": pkts["ICMP"].seq,
            "Origin timestamp": pkts["ICMP"].ts_ori,
            "Recieve timestamp": pkts["ICMP"].ts_rx,
            "Transmit timestamp": pkts["ICMP"].ts_tx,
        }
    else:
        return {
            "Protocol": "ICMP - Other/Unknown",
            "Type": icmp_type,
        }

def storePacket(packet):  # function to store parsed packets in json format
    with open("output.json", "w") as json_file:
        json.dump(packet, json_file, indent=4)

interface, count = get_args()
capPackets(interface, count)