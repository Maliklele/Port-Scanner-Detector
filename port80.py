
import nmap
nmScan = nmap.PortScanner()

ip='192.168.42.12'


r=nmScan.scan(ip, '80',sudo= '-F')


sPort = r['nmap']['scaninfo']['tcp']['services']
sTimeElapsed = r['nmap']['scanstats']['elapsed']
sPortState = r['scan'][ip]['tcp'][80]['state']
print("Port number: ",sPort)
print("Time Elapsed: ",sTimeElapsed+'s')
print("Port state: ",sPortState)