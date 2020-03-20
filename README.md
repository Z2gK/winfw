# wintools

A set of scripts to parse Windows command line output and help make sense of it.

## winfwparse.py

Parses the output of the windows `netsh advfirewall firewall show rule name=all` command and performs basic data exploration. Sample output file included.

TODO: Develop a basic and a pandas version

## fwexplore.py

Parses the output of the windows `netsh advfirewall firewall show rule name=all` command and shows some basic facts about the firewall rules.

## netstatparse.py

Parses the output of the windows `netstat -ano` command and outputs basic stats on connections. Requires the Linux `whois` command to run.

TODO: Integrate with the output of `tasklist /svc`, maybe in an improved version.
