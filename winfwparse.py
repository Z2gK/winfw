# This is the non pandas version
# To add argparse

#import sys
import argparse

parser = argparse.ArgumentParser(description="Basic exploration of windows firewall rules listed by the command netsh advfirewall firewall show rule name=all")
parser.add_argument("filename", type=str, help="filename of the text file containing the rules")
parser.add_argument("-n", "--num", action="store_true", help="Display number of rules")
parser.add_argument("-d", "--dump", action="store_true", help="Dump rules in python dictionary format")
parser.add_argument("-e", "--explore", action="store_true", help="Further quantitative exploration")


args = parser.parse_args()
filename = args.filename
nrules = 0

#if (len(sys.argv) != 2):
#    print("Argument: <filename>")
#    print("Enter the filename of a file containing the output of netsh advfirewall firewall show rule name=all")
#    exit()

fieldnames = set(['Protocol', 'Rule Name', 'Grouping', 'LocalIP', 'RemoteIP', 'Direction', 'Action', 'Edge traversal', 'Profiles', 'Enabled', 'LocalPort', 'RemotePort'])
# filename = sys.argv[1]

def numrules(filename):
    fp = open(filename,"r")
    global nrules
    nrules = 0
    for line in fp:
        s = line.strip()
        lst = s.split(":")
        if lst[0] == "Rule Name":
            nrules += 1
    fp.close()
    return nrules

def stats(filename):
    global nrules
    if (nrules == 0):
        nrules = numrules(filename)

    rules = {f:(['' for i in range(nrules)]) for f in fieldnames}

    fp = open(filename,"r")
    i = 0
    currenttag = ""
    # loop through every line
        # if tag is Rule Name, then set flag to start of rule - maybe we don't even need flag
            # parse fields for Rule Name and populate
            # set currenttag
        # select case tag
            # case is respective tags...
                # reset currenttag, fill in field
            # case is "        ", i.e. multiple line
                # use currenttag, append new info using ;
        # if tag is Action, i += 1, end flag
            # clear currenttag
    for line in fp:
        substr = line[0:15]
        if "Rule Name" in substr:
            currenttag = "Rule Name"
            data = line.split(":")[1:]
            rules["Rule Name"][i] = ":".join(data).strip()
        elif "Action" in substr:
            data = line.split(":")[1:]
            rules["Action"][i] = ":".join(data).strip()
            i += 1
            currenttag = ""
        elif (substr == "               "):
            data = line.strip()
            rules[currenttag][i] = rules[currenttag][i] + ";" + data
        elif substr.split(":")[0] in fieldnames:
            currenttag = substr.split(":")[0]
            data = ":".join(line.split(":")[1:]).strip()
            rules[currenttag][i] = data    
    
    # total number of rules, including disabled rules
    # number of enabled rules
    nenabled = rules["Enabled"].count("Yes")

    # of the enabled rules, what are the different rule groups and their counts?
    # of the enabled rules, how many allow and blocks?
    # of the enabled rules, how many In/Out directions?
    
    print("Total number of rules: {}".format(nrules))
    print("Number of enabled rules: {}".format(nenabled))

def dumprules(filename):
    global nrules
    if (nrules == 0):
        nrules = numrules(filename)

    rules = {f:(['' for i in range(nrules)]) for f in fieldnames}

    fp = open(filename,"r")
    i = 0
    currenttag = ""
    # loop through every line
        # if tag is Rule Name, then set flag to start of rule - maybe we don't even need flag
            # parse fields for Rule Name and populate
            # set currenttag
        # select case tag
            # case is respective tags...
                # reset currenttag, fill in field
            # case is "        ", i.e. multiple line
                # use currenttag, append new info using ;
        # if tag is Action, i += 1, end flag
            # clear currenttag
    for line in fp:
        substr = line[0:15]
        if "Rule Name" in substr:
            currenttag = "Rule Name"
            data = line.split(":")[1:]
            rules["Rule Name"][i] = ":".join(data).strip()
        elif "Action" in substr:
            data = line.split(":")[1:]
            rules["Action"][i] = ":".join(data).strip()
            i += 1
            currenttag = ""
        elif (substr == "               "):
            data = line.strip()
            rules[currenttag][i] = rules[currenttag][i] + ";" + data
        elif substr.split(":")[0] in fieldnames:
            currenttag = substr.split(":")[0]
            data = ":".join(line.split(":")[1:]).strip()
            rules[currenttag][i] = data    
    print(rules)


if args.num:
    print("Number of rules: {}".format(numrules(filename)))
    
if args.dump:
    dumprules(filename)

if args.explore:
    stats(filename)