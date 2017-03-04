#! /usr/bin/python

from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys
import getopt
from datetime import datetime
from time import strftime


def main():
    # Defaults:
    target = "127.0.0.1"
    port = 80
    localhost = "127.0.0.1"
    hostname = "www.byu.edu"
    if len(sys.argv) == 1:
        print "Welcome to Chris Rupper's Port Scanner"
        print "Please use the \'-h\' option for usage information!"
        sys.exit()
    try:
        # To add an option, add the short options to the list and add a ":" or a "="
        # to signal that there is additional input is expected
        opts, args = getopt.getopt(sys.argv[1:], "ho:vt:p:i:VTr:", ["help", "output=", "target=", "port=", "icmp_sweep=", "version", "test=", "sS", "sU", "check", "single", "pl=", "os"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print str(err)  # will print something like "option -a not recognized"
        sys.exit(2)
    output = None
    stealth = False
    udp_option = False
    tracert = False
    check = False
    single_target = False
    single_port = False
    rangeIsGiven = False
    portRangeIsGiven = False
    check_os = False
    for o, a in opts:
        if o == "-v":
            print "Verbosity has yet to be implemeted"
        elif o in ("-h", "--help"):
            print_help_message()
            sys.exit()
        elif o in ("-V", "--version"):
            print "Version 0.0.1"
            sys.exit()
        elif o in ("-t", "--target"):
            target = a
        elif o in ("-p", "--port"):
            port = a
            single_port = True
        elif o in ("-i", "--icmp_sweep"):
            ping_sweep(a)
            sys.exit()
        elif o in ("--test"):
            ping_host(a)
            sys.exit()
        elif o in ("--sS"):
            print "Stealth Scan"
            stealth = True
        elif o in ("--sU"):
            udp_option = True
        elif o in ("-T"):
            tracert = True
        elif o in ("--check"):
            check = True
        elif o in ("--single"):
            single_target = True
        elif o in ("-r"):
            rangeIsGiven = True
            host_range = a
        elif o in ("--pl"):
            raw_pl = a
            portRangeIsGiven = True
        elif o in ("--os"):
            check_os = True
        else:
            assert False, "unhandled option"
    # Basically main begins here:
    # One Port of Many?
    the_portlist = []
    if portRangeIsGiven:
        the_portlist = create_list_of_ports(raw_pl)
    # Single Targets
    if single_target:
        if (target != localhost):
            if check:
                checkhost(target)
                sys.exit()
            if stealth:
                if single_port:
                    stealth_scan(target, port)
                else:
                    handle_stealth_scan(target,the_portlist)
            if udp_option:
                if single_port:
                    udp_scan(target,port)
                else:
                    handle_udp_scan(target, the_portlist)
            if tracert:
                traceroute(hostname)
        else:
            print "Error! Improper use of arguments!" 
            print "Please view \'-h\' for usage information."
    else:
    # Multiple Targets
        if rangeIsGiven:
            the_hostlist = create_range_list(host_range)
        else:
            the_hostlist = create_list_of_hosts(target)
        if stealth:
            for host in the_hostlist:
                if single_port:
                    stealth_scan(host, port)
                else:
                    handle_stealth_scan(host,the_portlist)
        if udp_option:
            for host in the_hostlist:
                if single_port:
                    udp_scan(host, port)
                else:
                    handle_udp_scan(host, the_portlist)
        if tracert:
            for host in the_hostlist:
                traceroute(host)
    #check if OS detection is desired //nt
    if check_os:
        if (target != localhost):
            os_detection(target)
        else:
            for host in the_hostlist:
                os_detection(host)


# Functions

# tcp_scan is not functional yet and does not get called
def tcp_scan(given_target, given_port):
    dst_ip = given_target
    # src_port = RandShort()
    src_port = 0
    dst_port= given_port
    print "dst_ip: " + dst_ip 
    print "src_port: " + str(src_port)
    print "dst_port: " + dst_port
    tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
    if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
        print "Closed"
    elif(tcp_connect_scan_resp.haslayer(TCP)):
        if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
            print "Open"
    elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
        print "Closed"


def stealth_scan(given_target, given_port):
    # Uses Scapy to perform a stealth tcp scan
    ans = sr1(IP(dst=given_target) /TCP(dport=int(given_port)), timeout=1,verbose=0)
    if ans == None:
        pass
    else:
        if int(ans[TCP].flags) ==18:
            print given_port + " is open on " + given_target
        else:
            print given_port + " is closed on "+ given_target
            pass

# handle multiple ports given
def handle_stealth_scan(host,portlist):
    for port in portlist:
        stealth_scan(host, port)

def udp_scan(given_target, given_port):
    # Uses Scapy to perform UDP scan
    ans = sr1(IP(dst=given_target) /UDP(dport = int(given_port)), timeout=5,verbose=0)
    # wait for a response
    time.sleep(1)
    if ans == None:
        print given_port + " is open on "+ given_target
    else:
        pass

# handle multiple ports given
def handle_udp_scan(host, portlist):
    for port in portlist:
        udp_scan(host, port)

def checkhost(ip): 
    # Function to check if target is up
    ping_host(ip)
    sys.exit(1)

def ping_host(host):
    TIMEOUT = 2
    packet = IP(dst=host, ttl=20)/ICMP()
    reply = sr1(packet, timeout=TIMEOUT)
    if not (reply is None):
        print reply.src, "is online"
    else:
        print "Timeout waiting for %s" % packet[IP].dst

def ping_sweep(target_subnet):
    # this takes the subnet, and runs a ping on each host in that subnet
    hostlist = create_list_of_hosts(target_subnet)
    # print hostlist
    for host in hostlist:
        ping_host(host)

# Uses Scapy to implement Traceroute
def traceroute(hostname):
    for i in range(1, 28):
        pkt = IP(dst=hostname, ttl=i) / UDP(dport=33434)
        # Send and recieve one packet
        reply = sr1(pkt, verbose=0)
        if reply is None:
            # No reply =(
            break
        elif reply.type == 3:
            print "Done!", reply.src
            break
        else:
            # List distance from source
            print "%d hops away: " % i , reply.src

def os_detection(hostname):
    ans = sr1(IP(dst=hostname) /ICMP(), timeout=1, verbose=0)
    # The difference between Windows and Linux is the Standard TTL value
    # 64 on Linux, 128 on Windows 
    if ans ==None:
        print "No response returned"
    elif (int(ans[IP].ttl) <= 64):
        print "Host: " + hostname + " is a Linux/Unix machine"
    else:
        print "Host: " + hostname + " is a Windows machine"

# returns proper octet for CIDR
def find_max_octet(octet):
    if octet == "24":
        return "255"
    elif octet == "25":
        return "127"
    elif octet == "26":
        return "63"
    elif octet == "27":
        return "31"
    elif octet == "28":
        return "15"
    elif octet == "29":
        return "7"
    elif octet == "30":
        return "3"
    elif octet == "31":
        return "1"
    elif octet =="32":
        return "0"

# Takes the CIDR address given and returns list of IP address to target
def create_list_of_hosts(host_with_subnet):
#    print "Creating list of hosts:"
    subnet = host_with_subnet.split("/")
    splitter = subnet[0].split(".")
    init_string = splitter[0]+"."+splitter[1]+"."+splitter[2]+"."
    tail_octet = 0
    max_octet = int(find_max_octet(subnet[1]))
    hostlist = []
    # Once split, build the list
    for x in range(int(splitter[3]),max_octet+1):
        hostlist.append(init_string+str(x))

    return hostlist
  
# Takes the range given and returns list of IP address to target
def create_range_list(range_of_hosts):
    #Expected input: 192.168.207.41-42
    hostlist = []
    ip_split = range_of_hosts.split("-")
    splitter = ip_split[0].split(".")
    init_string = splitter[0]+"."+splitter[1]+"."+splitter[2]+"."
    # Once split, build the list
    for x in range(int(splitter[3]),int(ip_split[1])+1):
        hostlist.append(init_string+str(x))
    print hostlist
    return hostlist

# This function returns a list of strings (ports)
def create_list_of_ports(raw_pl):
    #Expected input: 1-1000
    portlist = []
    portEnds = raw_pl.split("-")
    # Once split, build the list
    for x in range(int(portEnds[0]),int(portEnds[1])+1):
        portlist.append(str(x))
    print portlist
    return portlist


# Displays the options for help
def print_help_message():
  print "To use the full capabilities of this program, please run as root!"
  print
  print """Options:\n
 -h\t\tHelp Message
--pl\t\tPort List- enter a range of ports (ex. 1-1000)

For Scanning a single target:
 -t\t\tTarget- enter the IP adress to scan
 -p\t\tPort- enter the port to scan
--single\tSpecify one host to be scanned

Types of Scans:
--sS\t\tStealth Scan
--sU\t\tUDP Scan
 -T\t\tTraceroute
 -i\t\tICMP Ping Sweep- Enter the subnet you wish to sweep in CIDR notation
--os\t\tOS Detection - enter one IP with -t or a range with -r

Miscellaneous:
 -v\t\tVerbose- gives added output
 -V\t\tVersion- print the version of this port scanner

"""

if __name__ == "__main__":
    main()

