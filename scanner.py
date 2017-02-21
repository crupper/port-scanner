#! /usr/bin/python

from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys
import getopt
from datetime import datetime
from time import strftime


def main():
    try:
        # To add an option, add the short options to the list and add a ":" or a "="
        # to signal that there is additional input is expected
        opts, args = getopt.getopt(sys.argv[1:], "ho:vt:", ["help", "output=", "target="])
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
            print target
        else:
            assert False, "unhandled option"
    # ...
    # Take in arguments
    print "Starting scan"

if __name__ == "__main__":
    main()
