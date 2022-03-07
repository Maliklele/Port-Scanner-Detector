
#ABDULMALIK ALSENANO
#201782610

import nmap
nmScan = nmap.PortScanner()

#Inputs
ip='1.1.1.1'
port=80

#Start the scan
r=nmScan.scan(ip, str(port))

#Get the results
sPort = r['nmap']['scaninfo']['tcp']['services']
sTimeElapsed = r['nmap']['scanstats']['elapsed']
sPortState = r['scan'][ip]['tcp'][port]['state']

#Print results
print("Port number: ",sPort)
print("Time Elapsed: ",sTimeElapsed+'s')
print("Port state: ",sPortState)