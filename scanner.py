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
    try:
        # To add an option, add the short options to the list and add a ":" or a "="
        # to signal that there is additional input is expected
        opts, args = getopt.getopt(sys.argv[1:], "ho:vt:p:iV", ["help", "output=", "target=", "port=", "info", "version"])
        # Intro message
        print "Hello!"
        print "Welcome to this port scanner"

    except getopt.GetoptError as err:
        # print help information and exit:
        print str(err)  # will print something like "option -a not recognized"
        # usage()
        sys.exit(2)
    output = None
    verbose = False
    for o, a in opts:
        if o == "-v":
            verbose = True
        elif o in ("-h", "--help"):
            # usage()
            print_help_message()
            sys.exit()
        elif o in ("-V", "--version"):
            print "Version 0.0.1"
            sys.exit()
        elif o in ("-t", "--target"):
            target = a
            # print target
        elif o in ("-p", "--port"):
            port = a
            # print port
        elif o in ("-i", "--info"):
            print target
            print port
        else:
            assert False, "unhandled option"
    # ...
    print "Starting scan"
    # print target
    # print port
    if (target != localhost):
#        icmp_ping(target)
#       checkhost(target)
        stealth_scan(target, port)
        udp_scan(target,port)
#        traceroute(hostname)
    else:
        print "Error" 
        print "Please enter the target IP and Port!"

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
    ans = sr1(IP(dst=given_target) /TCP(dport=int(given_port)), timeout=1,verbose=0)
    if ans == None:
        pass
    else:
        if int(ans[TCP].flags) ==18:
            print given_port + " is open"
        else:
            print "closed"
            pass

def udp_scan(given_target, given_port):
    ans = sr1(IP(dst=given_target) /UDP(dport = int(given_port)), timeout=5,verbose=0)
    time.sleep(1)
    if ans == None:
        print given_port + " is open"
    else:
        pass


def checkhost(ip): # Function to check if target is up
        conf.verb = 0 # Hide output
        try:
                ping = sr1(IP(dst = ip)/ICMP()) # Ping the target
                print "\n[*] Target is Up, Beginning Scan..."
        except Exception: # If ping fails
                print "\n[!] Couldn't Resolve Target"
                print "[!] Exiting..."
                sys.exit(1)


def icmp_ping(host):
    ''' ICMP Ping '''

    # Classical ICMP Ping can be emulated using the following command:
    ans, unans = sr(IP(dst=host)/ICMP())

    # Information on live hosts can be collected with the following request:
    ans.summary(lambda (s, r): r.sprintf("%IP.src% is alive"))



def traceroute(hostname):
    for i in range(1, 28):
        pkt = IP(dst=hostname, ttl=i) / UDP(dport=33434)
        # Send the packet and get a reply
        reply = sr1(pkt, verbose=0)
        if reply is None:
            # No reply =(
            break
        elif reply.type == 3:
            # We've reached our destination
            print "Done!", reply.src
            break
        else:
            # We're in the middle somewhere
            print "%d hops away: " % i , reply.src


def print_help_message():
  print """Options:\n
-h\t\tHelp Message
-t\t\tTarget- enter the IP adress to scan
-p\t\tPort- enter the port to scan
-i\t\tInformation- print target and port
-v\t\tVerbose- gives added output
-V\t\tVersion- print the version of this port scanner
"""

if __name__ == "__main__":
    main()


# more things to implement:
#   dig
#   arp?
#   ping
#   

