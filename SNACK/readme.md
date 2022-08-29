<p align="Center"><img src="https://github.com/Capt-Rog/SNACK/blob/master/SNACK/Images/snack_logo.png?raw=true" width="150"/></p>

<h1 align="center" style="color:green;font-size:75px;"><em>Simple Network Automated Communications Kit</em></h1>

### _*Description*:_
    SNACK was designed to perform complex network interactions in simple easy to use tool.
    This tool can perform packet crafting, tcp port scans, os discovery scans, and more! 
    See Usage below! 

### _*Imports*_:
    Built on Python 3.10
   <p><img src=https://github.com/Capt-Rog/SNACK/blob/master/SNACK/Images/imports.png?raw=true" width="300"/></p>

### _*Usage:*_
    Ex. "sudo python3 snack.py -t 192.168.1.1 -oscn" (This will return information
    about the operating system) 
   _Options:_
   1. -t (this is used to designate your target)
   2. -hscn (this argument can is used to scan either a single IPv4 address or
   IPv4 subnet using ICMP to determine if the host is present and responding ICMP)
   3. -pscn (this argument will perform at _TCP Port_ scan on a designated target)
   4. -oscn (this argument will query and return information about the host's OS)
   5. -pc (this argument requires one additional argument, but can take two. First
   you must specify the layer 3/4 (TCPIP vs OSI) protocol using -tcp, -icmp, or 
   -udp. This function will allow for you to transmit a custom packet with a 
   custom payload. _*The terminal will prompt you for additional information.*_)
    
<p><img src="https://github.com/Capt-Rog/SNACK/blob/master/SNACK/Images/arguments.png?raw=true" width="800"/></p>

### _*Configuration/Troubleshooting:*_

#####1. Common Error (Resolving MAC addresses): 
    Warning: "MAC Address to reach destination not found. Using broadcast."
    
This error occurs when the tool is unable to resolve the broadcast address for your request
via the ARP table. You can fix this by changing your request from sr (send receive) to srp 
which will send that information for you via transmitting the layer 2 information you designate.
In addition to changing to srp include the "Ether" layer in the request with the
destination set as follows: dst="FF:FF:FF:FF:FF:FF"
    
    Ex. srp(Ether(dst="FF:FF:FF:FF:FF:FF")/IP(dst=target)/ICMP(id=100), timeout=2)
    
####2. Mac OS Functionality Issues (sniff(filter="@nything"")):
<p><img src="https://github.com/Capt-Rog/SNACK/blob/master/SNACK/Images/libpcap_error.png?raw=true" width="800"/></p>
This error occurs because backend functionality in dyld_find does not search any of the directories
that _brew_ installs libpcap into. To fix this you can move one of the following files to usr/local/lib/

* libpcap.dylib
* pcap.dylib
* pcap.framework/pcap

_Note: The OS detection function in this tool is currently using nmap3 and parsing the dictionary
that is returned, but a later version will be using the fixed sniff() function which should allow
for a more robust formatted output._ 
    
    Source: https://stackoverflow.com/questions/65030510/filter-in-scapy-function-sniff-says-libpcap-is-not-available
