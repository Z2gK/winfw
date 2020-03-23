# UNDER CONSTRUCTION!

# What process is connecting to where?

import subprocess
import argparse
# import re

parser = argparse.ArgumentParser(description="Basic exploration of the command netstat -ano and tasklist /svc. Only lines for TCP connections in the netstat output will be parsed for now. The destination should be of the form w.x.y.z:P, where x.w.y.z is some internal or external IP (and not localhost or 0.0.0.0). The PIDs from netstat will be matched to those from tasklist.")
parser.add_argument("netstatfn", type=str, help="filename of the text file containing the netstat -ano output.")
parser.add_argument("tasklistfn", type=str, help="filename of the text file containing the tasklist /svc output.")

args = parser.parse_args()
netstatfn = args.netstatfn
tasklistfn = args.tasklistfn

print("netstat file: {}".format(netstatfn))
print("tasklist file: {}".format(tasklistfn))

# parse the tasklist file first
# Returns a dictionary
def parsetasklist(tasklistfn):
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
                print("{} {}".format(imgname_pid, service))


    # print("size of dictionary = {}".format(len(d)))
    # print(d)
    return d

# TODO: write netstat code and take PID into account
