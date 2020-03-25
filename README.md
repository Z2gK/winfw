# wintools

A set of scripts to parse Windows command line output and help make sense of it.

## winfwparse.py

Parses the output of the windows `netsh advfirewall firewall show rule name=all` command and performs basic data exploration. Sample output file included.

TODO: Develop a basic and a pandas version

## fwexplore.py

Parses the output of the windows `netsh advfirewall firewall show rule name=all` command and shows some basic facts about the firewall rules.

## netstatprocess.py

Basic exploration of the command netstat -ano and tasklist /svc. Only lines for TCP connections in the netstat output will be parsed for now. The destination should be of the form w.x.y.z:P, where x.w.y.z is some internal or external IP (and not localhost or 0.0.0.0). The PIDs from netstat will be matched to those from tasklist.

This script was built from two simpler ones: `netstatparse.py` and `tasklistparse.py`.

### netstatparse.py

Parses the output of the windows `netstat -ano` command and outputs basic stats on connections. Requires the Linux `whois` command to run.

### tasklistparse.py

Script to produce a dictionary of PID:process.

