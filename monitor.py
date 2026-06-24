from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from ipwhois import IPWhois


traffic_counter = defaultdict(int)

ip_cache = {}


# Function to get IP information
def resolve_ip(ip):

    if ip in ip_cache:
        return ip_cache[ip]


    try:
        obj = IPWhois(ip)

        result = obj.lookup_rdap()


        info = {
            "asn": result.get("asn"),
            "org": result.get("network", {}).get("name"),
            "country": result.get("network", {}).get("country")
        }


    except Exception:

        info = {
            "asn": None,
            "org": "Unknown",
            "country": "Unknown"
        }


    ip_cache[ip] = info

    return info



# Packet analysis function
def process(packet):

    if packet.haslayer(IP):

        ip = packet[IP]


        protocol = "OTHER"


        if packet.haslayer(TCP):

            protocol = "TCP"


        elif packet.haslayer(UDP):

            protocol = "UDP"



        key = (ip.src, ip.dst, protocol)


        traffic_counter[key] += 1



        src_info = resolve_ip(ip.src)

        dst_info = resolve_ip(ip.dst)



        print("\nPacket Detected:")

        print(
            f"{ip.src} ({src_info['org']}) "
            f"-> "
            f"{ip.dst} ({dst_info['org']}) "
            f"| Protocol: {protocol} "
            f"| Count: {traffic_counter[key]}"
        )



# START PACKET CAPTURE
sniff(prn=process, store=0)