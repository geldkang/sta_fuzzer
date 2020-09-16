from datetime import datetime
import os
import sys
import subprocess

# Defining fuzzing specific variables
STA_MAC = sys.argv[1].lower()  # '40:4e:36:8e:b1:ce 7c:dd:90:ef:cd:48"
REPEAT_TIME = 1

# dummy ap
AP_DUMMY = sys.argv[2].lower()

# Defining the injection interface
if len(sys.argv) == 3:
    try:
        iwcfg = subprocess.check_output('iwconfig')
    except Exception, e:
        print '[-] Failed to get wireless adapter information'
        sys.exit(1)

    if 'IEEE 802.11' in iwcfg:
        iwlist = iwcfg.split()
        IFACE = iwlist[0]
        if not 'Mode:Monitor' in iwlist:
            try:
                os.system('sudo ifconfig '+IFACE+' down')
                os.system('sudo iwconfig '+IFACE+' mode monitor')
                os.system('sudo ifconfig '+IFACE+' up')
            except Exception, e:
                print '[-] Failed to set wireless adapter to Monitor mode'
                sys.exit(1)
    else:
        print '[-] No wireless adapters found. Please check you have available one.'
        sys.exit(1)
else:
    IFACE = sys.argv[3].lower()
    try:
        iwcfg = subprocess.check_output(['iwconfig', IFACE])
    except Exception, e:
        print '[-] Failed to get ' + IFACE + ' information'
        sys.exit(1)

    if IFACE in iwcfg:
        iwlist = iwcfg.split()
        if not 'Mode:Monitor' in iwlist:
            try:
                os.system('sudo ifconfig '+IFACE+' down')
                os.system('sudo iwconfig '+IFACE+' mode monitor')
                os.system('sudo ifconfig '+IFACE+' up')
                print '[+] Device set to Monitor mode'
            except Exception, e:
                print '[-] Failed to set wireless adapter to Monitor mode'
                sys.exit(1)
    else:
        print '[-] No wireless adapters found. Please check you have available one.'
        sys.exit(1)

if not len(sys.argv) in [3, 4]:
    print "Usage: sudo python fuzz_sta.py [target MAC] [DummyAP MAC] [Wireless Adapter name]"
    sys.exit(1)

# Tuning listen value (fuzzing speed and false positive rates)
LISTEN_TIME = 10

tool_version = "1.0.0"

year = datetime.today().year
month = datetime.today().month
day = datetime.today().day
hour = datetime.today().hour
minute = datetime.today().minute
second = datetime.today().second
microsecond = datetime.today().microsecond
starting_time = "{0}-{1}{2} {3}:{4}:{5}.{6}".format(year, month, day, hour, minute,second, microsecond)

if not os.path.exists("./logs"):
    os.makedirs("./logs")

log_file_name = "./logs/log_{0}_{1}_{2}_{3}-{4}-{5}-{6}.wfl".format(year, month, day, hour,minute,second,microsecond)
log_file = open(log_file_name,"w")
log_file.write("{\n")
log_file.write("\t\"toolVer\" : \"{0}\",\n".format(tool_version))
log_file.write("\t\"interface\" : \"Wi-Fi(STA)\",\n")
log_file.write("\t\"sta_mac\" : \"{0}\",\m\n".format(STA_MAC))
log_file.write("\t\"starting_time\" : \"{0}-{1}-{2} {3}:{4}:{5}.{6}\",\n".format(year, month, day,hour,minute,second,microsecond))
log_file.write("\t\"protocol\" : \"802.11\",\n")
log_file.write("\t\"packet\" : [\n")
log_file.close()

