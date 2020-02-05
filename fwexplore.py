# Some basic facts about the output of
# netsh advfirewall firewall show rule name=all

import sys

if (len(sys.argv) != 2):
    print("Argument: <filename>")
    print("Enter the filename of a file containing the output of netsh advfirewall firewall show rule name=all")
    exit()
    
filename = sys.argv[1]
fp = open(filename, "r")

# Preliminary exploration

# How many rules are there?
# Count number of occurence of "Rule Name"
count = 0
for line in fp:
    s = line.strip()
    lst = s.split(":")
    if lst[0] == "Rule Name":
        count += 1
print("Number of rules: {}".format(count))
fp.close()
# Number of rules: 653

# what are the fields?
fp = open(filename,"r")
print("What are the fields in the output?")
fieldnameset = set()
for line in fp:
    s = line.strip()
    if (s != ""):
        lst = s.split(":")
        if(len(lst) != 1):
            if not(lst[0] in fieldnameset):
                fieldnameset.add(lst[0])

print(fieldnameset)
# Result:
# There are 12 fields in this sample. LocalPort and RemotePort are missing from some
# {'Protocol', 'Rule Name', 'Grouping', 'LocalIP', 'RemoteIP', 'Direction', 'Action', 'Edge traversal', 'Profiles', 'Enabled', 'LocalPort', 'RemotePort'}
fp.close()



# Some fields look like factor data types
# It looks like - 
# Enabled: Yes or No
# Direction: In/Out
# Protocol: Any/TCP/UDP - no could be multiple lines ICMPv6
# Edge traversal: Yes/No
# Action: Allow and ?? (don't think there are any drop rules)


fp = open(filename, "r")
extract = set(["Enabled","Direction","Edge traversal","Action"])
d = {s: set() for s in extract}

for line in fp:
    s = line.strip()
    if (s != ""):
        lst = s.split(":")
        if (len(lst) != 1):
            if lst[0] in extract:
                item = lst[1].strip()
                if not(item in d[lst[0]]):
                    d[lst[0]].add(item)
                
print(d)
# Result:
# {'Direction': {'In', 'Out'}, 'Action': {'Block', 'Allow'}, 'Enabled': {'No', 'Yes'}, 'Edge traversal': {'Defer to application', 'No', 'Yes'}}
fp.close()

# Which fields have multiple lines?
fp = open(filename,"r")
fieldnames = set(['Protocol', 'Rule Name', 'Grouping', 'LocalIP', 'RemoteIP', 'Direction', 'Action', 'Edge traversal', 'Profiles', 'Enabled', 'LocalPort', 'RemotePort'])
pickedfields = set(['Protocol', 'Grouping', 'LocalIP', 'RemoteIP', 'Direction', 'Action', 'Edge traversal', 'Profiles', 'Enabled', 'LocalPort', 'RemotePort'])
savedentries = []
currentfield = ""
for line in fp:
    substring = line[0:15]
    # If encounter a start tag (including Action)
    #     if start tag is different from previous tag, 
    #        print field and entries only if the length of savedentries > 1
    #        put data in savedentries, reset currentfield if not Action tag
    # else if encounter a string of spaces
    #     append data to saved entries.
    if sum([s in substring for s in pickedfields]):
        currenttag = substring.split(":")[0]
        if (currenttag != currentfield):
            if (len(savedentries) > 1):
                print("Fieldname: {}".format(currentfield))
                print(savedentries)
            if not(currenttag == "Action"):
                currentfield = currenttag
                savedentries = [line.split(":")[1].strip()]
    elif (substring == "               "):
        savedentries.append(line.strip())


# What groupings are there?
# Why are some rules Enabled and some not?
# save rules to pickle object or csv??
