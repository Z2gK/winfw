# WTF am I connecting to?
# This script runs in Linux and requires whois to be installed

import subprocess
import argparse
import re

# Search for "org-name" or "OrgName"
def findOrg(s):
    lst = s.split("\n")
    # print(lst)
    orgname = ""
    for r in lst:
        if (   (r.split(":")[0].lower() == "org-name") or (r.split(":")[0].lower() == "orgname") ):
            orgname = r.split(":")[1].strip()
            break
    return orgname


parser = argparse.ArgumentParser(description="Basic exploration of the command netstat -ano. Only lines for TCP connections will be parsed for now. The destination should be of the form w.x.y.z:P, where x.w.y.z is some internal or external IP (and not localhost or 0.0.0.0)")
parser.add_argument("filename", type=str, help="filename of the text file containing the output. This can be partial or complete output")
#parser.add_argument("-n", "--num", action="store_true", help="Display number of rules")
#parser.add_argument("-d", "--dump", action="store_true", help="Dump rules in python dictionary format")
#parser.add_argument("-e", "--explore", action="store_true", help="Further quantitative exploration")

args = parser.parse_args()
filename = args.filename

# bad regex for IPv4 addressess
p = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}")

# this shall be a dictionary with values being dictionaries
# to store the ip addresses, then the ports and their frequencies of occurence
d = {}

# fp = open(filename, "r")
with open(filename, "r") as fp:
    for line in fp:
        s = line.strip()
        lst = s.split()
        if ((len(lst) > 0) and (lst[0] == "TCP")):
            m = p.match(lst[2])
            if m:
                (ip, port) = lst[2].split(":")
                port = int(port)
                if ((ip != "127.0.0.1") and (ip != "0.0.0.0")):
                    if ip in d.keys():
                        if port in d[ip]:
                            # add to count
                            d[ip][port] = d[ip][port] + 1                            
                        else:
                            # add new port as key
                            d[ip][port] = 1
                    else:
                        d[ip] = {}
                        d[ip][port] = 1
                    
# print(d)
print("Number of unique IPs: {}".format(len(d)))
for k, v in d.items():
    # get whois data
    out = subprocess.Popen(['whois', k], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, sterr = out.communicate()
    # print(str(stdout))
    org = findOrg(str(stdout,encoding='utf-8'))
    print("{} {} {}".format(k, v, org))
