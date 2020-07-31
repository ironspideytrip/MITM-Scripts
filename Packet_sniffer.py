import scapy.all as scapy
import netfilterqueue
def process_packet(packet):
	scapy_packet=scapy.IP(packet.get_payload())
	if scapy_packet.haslayer(scapy.DNSRR):
		print(scapy_packet.show())
        packet.accept()
queue=netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet)
queue.run()	
