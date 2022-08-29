# This is the current build of SNACK or "Simple Network Automated Communication Kit"
import time
import argparse
import re
from scapy.all import *
import nmap3
import random

parser = argparse.ArgumentParser(description='SNACK - Simple Network Automated Communication Kit')
parser.add_argument('-t', '--target', required=True, type=str, help='designate your target IP or subnet. Ex. 10.10.10.12 OR 10.10.10.0/24')
parser.add_argument('-hscn', '--host_discovery_scan', action='store_true', help='Detects hosts responding to ICMP (will potentially miss hosts configured not to respond to ICMP)')
parser.add_argument('-pscn', '--port_scan', action='store_true', help='Detects open TCP ports on a single target')
parser.add_argument('-oscn', '--os_scan', action='store_true', help='This will detect the OS of a single target, do not use a subnet designation')
parser.add_argument('-pcap', '--packet_capture', action='store_true', help='Captures traffic and outputs a .pcap file')
parser.add_argument('-asd', '--anomalous_service_detection', action='store_true', help='Looks for open ports that are not associated with any specific service')
parser.add_argument('-pc', '--packet_crafting', action='store_true', help='Allows you to craft a custom layer 4 packet and send it to your designated target')
parser.add_argument('-of', '--output_file', action='store_true', help='Outputs a file instead of printing to console')
parser.add_argument('-co', '--console_output', action='store_true', help='Will output results to the console instead of a file')
parser.add_argument('-udp', '--user_datagram_protocol', action='store_true', help='Used to designate the layer 4 protocol udp in packet crafting')
parser.add_argument('-tcp', '--transmission_control_protocol', action='store_true', help='Used to designate the layer 4 tcp protocol in packet crafting')
parser.add_argument('-spf', '--spoof_source', action='store_true', help='will allow you to spoof source IP address for packet crafting')
parser.add_argument('-icmp', '--internet_control_message_protocol', action='store_true', help='Used to designate the layer 4 icmp protocol in packet crafting')
parser.add_argument('-http', '--http_request', action='store_true', help='This function is used to transmit custom http requests')
args = parser.parse_args()


def scans(target):

    if args.host_discovery_scan:
        print("Initiating ICMP Host Discovery Scan....")
        ans, unans = srp(Ether(dst="FF:FF:FF:FF:FF:FF")/IP(dst=target)/ICMP(id=100), timeout=2)
        ans.summary(lambda s, r: (s.sprintf("IP: %IP.dst% responded to ICMP")))
        print("ICMP host discovery scan complete")
        quit()

    elif args.port_scan:
        dst = target
        print("Initiating Common Port Scan....")
        for dst_port in range(1, 4000):
            src_port = random.randint(8000, 65534)
            resp = sr1(IP(dst=target)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1,verbose=0)

            if resp is None:
                #If no response is received port is likely filtered by a firewall or other device
                print(f"{dst}:{dst_port} filtered")

            elif(resp.haslayer(TCP)):
                #SYN ACK indicates target accepted the traffic on the designated port
                if(resp.getlayer(TCP).flags == "SA"):
                    #Close connection
                    sr(IP(dst=target) / TCP(sport=src_port, dport=dst_port, flags='R'),timeout=1,verbose=0,)
                    print(f"{target}:{dst_port} is open.")

                elif (resp.getlayer(TCP).flags == "RA"):
                    #RST ACK flags indicate that a port is closed
                    pass
                    #Could do args to print this out if wanted, revisit this
                    #print(f"{target}:{dst_port} is closed.")
        print("port scan complete")
        quit()

    elif args.os_scan:
        x = nmap3.Nmap()
        os = x.nmap_os_detection(target)
        ost = (os[target]['osmatch'])
        print(ost[0])
        osv = (os[target]['macaddress'])
        print(osv)
        quit()

    elif args.anomalous_service_detection:
        print("Anomalous Service Detection Initiated....")
        dst = target
        for port in range(1024, 42151):
            src_port = random.randint(8000, 65534)
            resp = sr1(IP(dst=target) / TCP(sport=src_port, dport=port, flags="S"), timeout=1, verbose=0)

            if resp is None:
                # If no response is received port is likely filtered by a firewall or other device
                print(f"{dst}:{port} filtered")

            elif (resp.haslayer(TCP)):
                # SYN ACK indicates target accepted the traffic on the designated port
                if (resp.getlayer(TCP).flags == "SA"):
                    # Close connection
                    sr(IP(dst=target) / TCP(sport=src_port, dport=port, flags='R'), timeout=1, verbose=0, )
                    print(f"{target}:{port} is open.")

                elif (resp.getlayer(TCP).flags == "RA"):
                    # RST ACK flags indicate that a port is closed
                    pass
        print("Scanning Complete!")
        quit()

    else:
        craft(target)


def craft(target):
    if args.packet_crafting:
        src_port = random.randint(8000, 65534)
        if not (args.transmission_control_protocol or args.user_datagram_protocol or args.internet_control_message_protocol):
            print("please retry after selecting -tcp, -icmp or -udp")
        elif args.spoof_source:
            source = input("Please enter your desired source IP address: ")
            y = input("Please input your desired destination port:")
            port = int(y)
            payload = input("Please provide your payload:")

            if args.transmission_control_protocol:
                flag = input("Please input your desired TCP flags (ex. RA OR SA OR S): ")
                ans, unans = srp(Ether(src="FF:FF:FF:FF:FF:FF")/IP(dst=target, src=source)/TCP(sport=src_port, dport=port, flags=flag)/payload, timeout=2)
                ans.show()
            elif args.user_datagram_protocol:
                ans, unans = srp(Ether(src="FF:FF:FF:FF:FF:FF")/IP(dst=target, src=source)/UDP(sport=src_port, dport=port)/payload, timeout=2)
                ans.show()
            elif args.internet_control_message_protocol:
                ans, unans= srp(Ether(dst="FF:FF:FF:FF:FF:FF")/IP(src=source, dst=target)/ICMP(id=100)/payload, timeout=2)
                ans.show()
        elif not args.spoof_source:
            y = input("Please input your desired destination port:")
            port = int(y)
            payload = input("Please provide your payload:")

            if args.transmission_control_protocol:
                flag = input("Please input your desired TCP flags (ex. RA OR SA OR S): ")
                ans, unans = srp(Ether(src="FF:FF:FF:FF:FF:FF") / IP(dst=target) / TCP(sport=src_port, dport=port, flags=flag) / payload, timeout=2)
                ans.show()
            elif args.user_datagram_protocol:
                ans, unans = srp(Ether(src="FF:FF:FF:FF:FF:FF")/IP(dst=target)/UDP(sport=src_port, dport=port)/payload, timeout=2)
                ans.show()
            elif args.internet_control_message_protocol:
                ans, unans= srp(Ether(dst="FF:FF:FF:FF:FF:FF")/IP(dst=target)/ICMP(id=100)/payload, timeout=2)
                ans.show()
        else:
            quit()

    elif args.http_request:
        load_layer("http")
        uri = input("Please provide a uniform resource identifier: (If none use '/')")
        http_request(target, uri, display=False)

    else:
        print("No action selected, try -hscn, oscn, etc.")
        time.sleep(15)
        quit()


def outputs(file):
    if args.output_file:
        print("file")
        print(file)
        quit()
        #output return as text file
    else:
        quit()

if __name__ == '__main__':
    target = args.target
    ip = re.search("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", target)
    ipsub = re.search("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}][/0-9]{2,3})", target)
    notallowed = re.search("([a-zA-Z!@#\$%\^&\*\(\)\-\+=_\?\>\<\"\:])", target)
    if (ip is None and ipsub is None) or notallowed is not None:
        print("Target must be in the form of an IPv4 address or IPv4 address and subnet designation Ex. 192.168.0.1/24")
        time.sleep(15)
        quit()
    elif (args.host_discovery_scan or args.port_scan or args.os_scan or args.anomalous_service_detection) and args.packet_crafting:
        print("Not allowed")
        time.sleep(15)
        quit()
    elif not (args.host_discovery_scan or args.port_scan or args.os_scan or args.packet_crafting or args.anomalous_service_detection or args.packet_capture):
        print("No command given, try -hscn, -pscn, -oscn, -asd, or -pc....")
    else:
        print("Executing Commands....")
        scans(target)

