# port-scanner

###Scans:

Stealth TCP

UDP

ICMP - Ping Sweep

Traceroute

Xmas Scan

OS Detection

---

###Options

Options:


```
 -h             Help Message
--pl            Port List- enter a range of ports (ex. 1-1000)

For Scanning a single target:
 -t             Target- enter the IP adress to scan
 -p             Port- enter the port to scan
--single        Specify one host to be scanned

Types of Scans:
--sS            Stealth Scan
--sU            UDP Scan
 -T             Traceroute
 -i             ICMP Ping Sweep- Enter the subnet you wish to sweep in CIDR notation
 -x             Xmas Scan
--os            OS Detection - enter one IP with -t or a range with -r

Miscellaneous:
 -v             Verbose- gives added output
 -V             Version- print the version of this port scanner
```

---

###Example Usage


```
sudo python scanner.py -r 192.168.1.1-99 --pl 1-1000 --sS --os -x
```

######Created by: Chris Rupper
