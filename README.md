# wifi sta fuzzer
based on wifuzzit
do fuzzing test on wifi station by sending random packets

Instructions
1. disguise to access point by sending deceiving packets to station
2. make wifi connection with station
3. disable connection, go back to 1

during each states(unconnected, connecting, connected), random packets sent to fuzz each wifi connection state of station
