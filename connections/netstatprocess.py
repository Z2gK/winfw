# UNDER CONSTRUCTION!

# What process is connecting to where?

import subprocess
import argparse
import re

parser = argparse.ArgumentParser(description="Basic exploration of the command netstat -ano and tasklist /svc. Only lines for TCP connections in the netstat output will be parsed for now. The destination should be of the form w.x.y.z:P, where x.w.y.z is some internal or external IP (and not localhost or 0.0.0.0). The PIDs from netstat will be matched to those from tasklist.")
parser.add_argument("netstatfn", type=str, help="filename of the text file containing the netstat -ano output.")
parser.add_argument("tasklistfn", type=str, help="filename of the text file containing the tasklist /svc output.")
parser.add_argument("-w", "--whois", action="store_true", help="Resolve organisation name using whois for IP addresses")

args = parser.parse_args()
netstatfn = args.netstatfn
tasklistfn = args.tasklistfn

print("netstat file: {}".format(netstatfn))
print("tasklist file: {}".format(tasklistfn))

# parse the tasklist file first
# Returns a dictionary
def parsetasklist(tasklistfn):
    d = {}
    with open(tasklistfn, "r") as fp:
        line = fp.readline().strip()
        while line != "========================= ======== ============================================":
            line = fp.readline().strip()
            continue
        for line in fp:
            if len(line) > 34:
                s = line
                imgname_pid = s[:34] # Image Name and PID fields are from col 1 to 34 inclusive
                service = s[35:].strip()   # parse service
                # parse imgname_pid
                if imgname_pid.strip() != "":
                    rpos = imgname_pid.rfind(" ")
                    imgname = imgname_pid[:rpos].strip()
                    pid = int(imgname_pid[rpos:])
                    d[pid] = (imgname, service) # create a new entry
                    prevpid = pid
                else:
                    # in this case we append the service or we ignore
                    if (service != ""):
                        newservice = d[prevpid][1] + service
                        d[prevpid] = (imgname, newservice)

                #print(pid)
                #print("{} {}".format(imgname_pid, service))


    # print("size of dictionary = {}".format(len(d)))
    # print(d)
    return d

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

# TODO: write netstat code and take PID into account
tasklistdict = parsetasklist(tasklistfn)
# print(d)

# netstat part
# we want two dictionaries here:
# d: {IP: {port: frequency of occurence}}
# p: {IP: {port: (PIDs)}}
def parsenetstat(netstatfn):
    # bad regex for IPv4 addressess
    reg = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}")
    d = {}
    p = {}
    with open(netstatfn, "r") as fp:
        for line in fp:
            s = line.strip()
            lst = s.split()
            if ((len(lst) > 0) and (lst[0] == "TCP")):
                m = reg.match(lst[2])
                if m:
                    (ip, port) = lst[2].split(":")
                    port = int(port)
                    pid = int(lst[4])                    
                    if ((ip != "127.0.0.1") and (ip != "0.0.0.0")):
                        # Do IP vs ports
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
                        # now lets do IP vs PIDs
                        if ip in p.keys():
                            #print(ip)
                            if port in p[ip]:
                                # if pid does not exist
                                if not(pid in p[ip][port]):
                                    s = p[ip][port].copy()
                                    s.append(pid)
                                    p[ip][port] = s
                            else:
                                p[ip][port] = [pid]
                        else:
                            #print(ip)
                            p[ip] = dict({port: [pid]})
                #print(p)

    return (d,p)
                            
(portdict,piddict) = parsenetstat(netstatfn)
#print("ports and frequency of occurence")
#print(portdict)
#print("pids")
#print(piddict)

print("Number of unique IPs: {}".format(len(piddict)))
print("Number of unique IPs: {}".format(len(portdict)))

# print IPs ports, PIDs, process names
for (ip, v1) in piddict.items():
    org = ""
    if args.whois:
            out = subprocess.Popen(['whois', ip], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            stdout, sterr = out.communicate()
            org = findOrg(str(stdout,encoding='utf-8'))
            org = " (" + org + ")"
            
    for port, pidlist in v1.items():
        ipport = "{}:{}".format(ip,port)
        for pid in pidlist:
            # print(type(pid))
            processes = ""
            if pid in tasklistdict.keys():
                processes = "{}:{}".format(tasklistdict[pid][0], tasklistdict[pid][1])
            #print("{0:25} {1:10d} {} {}".format(ipport, pid, processes, org))
            print("{0:23} {1:7d} {2:30}".format(ipport, pid, processes + org))
