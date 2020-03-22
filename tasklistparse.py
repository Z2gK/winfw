# parse the output of tasklist /svc to produce a dictionary of PIDs and process/service names
# code to be integrated into netstatparse.py eventually
import argparse

parser = argparse.ArgumentParser(description="Parse the output of tasklist /svc and produces a dictionary of PID vs process/service names.")
parser.add_argument("filename", type=str, help="filename of the text file containing the output.")

args = parser.parse_args()
filename = args.filename

# dictionary holding what we want
# {PID: (imgname-str, service-str)}
d = {}

with open(filename, "r") as fp:
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
            

print("size of dictionary = {}".format(len(d)))
print(d)

# Sample output
#System Idle Process              0 N/A                                         
#System                           4 N/A                                         
#Registry                       120 N/A                                         
#smss.exe                       416 N/A                                         
#csrss.exe                      668 N/A                                         
#wininit.exe                    752 N/A                                         
#services.exe                   828 N/A                                         
#lsass.exe                      836 EFS, KeyIso, Netlogon, SamSs, VaultSvc      
    
