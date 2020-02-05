# This is the non pandas version
# To add argparse

import sys

if (len(sys.argv) != 2):
    print("Argument: <filename>")
    print("Enter the filename of a file containing the output of netsh advfirewall firewall show rule name=all")
    exit()


fieldnames = set(['Protocol', 'Rule Name', 'Grouping', 'LocalIP', 'RemoteIP', 'Direction', 'Action', 'Edge traversal', 'Profiles', 'Enabled', 'LocalPort', 'RemotePort'])
