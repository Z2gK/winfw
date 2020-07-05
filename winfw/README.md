# winfw

A set of scripts to help analyse Windows firewall rules and help make sense of it.

## winfwparse.py

Parses the output of the windows `netsh advfirewall firewall show rule name=all` command and performs basic data exploration. Sample output file included.

TODO: Develop a basic and a pandas version

## fwexplore.py

Parses the output of the windows `netsh advfirewall firewall show rule name=all` command and shows some basic facts about the firewall rules.
