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
    try:
        # To add an option, add the short options to the list and add a ":" or a "="
        # to signal that there is additional input is expected
        opts, args = getopt.getopt(sys.argv[1:], "ho:vt:p:", ["help", "output=", "target=", "port="])
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
            print "Help: "
            sys.exit()
        elif o in ("-o", "--output"):
            output = a
        elif o in ("-t", "--target"):
            target = a
            # print target
        elif o in ("-p", "--port"):
            port = a
            # print port
        else:
            assert False, "unhandled option"
    # ...
    print "Starting scan"
    # print target
    # print port
    tcp_scan(target, port)

def tcp_scan(given_target, given_port):
    dst_ip = given_target
    # src_port = RandShort()
    src_port = 0
    dst_port= given_port
    print "Variables:\n " + dst_ip 
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


if __name__ == "__main__":
    main()


# more things to implement:
#   dig
#   arp?
#   ping
#   

