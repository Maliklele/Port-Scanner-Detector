
from time import sleep
from scapy.all import sniff
import pandas as pd
import threading
import os



clearConsole = lambda: os.system('cls' if os.name in ('nt', 'dos') else 'clear')


packetsData = pd.DataFrame(columns=['src','sport'])
caughtPortDetectionHost = []

UNIQUE_REQUESTS_FLAG=15
CONSECUTIVE_PORTS_FLAG=15
SCAN_TIME=5
## Create a Packet Counter

def custom_action(packet):
    global packetsData
    # Create tuple of Src/Dst in sorted order
    if hasattr(packet.payload, "src") and hasattr(packet.payload, "sport"):
        
        packet = pd.DataFrame({"src":[packet[0][1].src],"sport":[packet[0][1].sport]})
        packetsData = pd.concat([packetsData,packet])


def findLongestConseqSubseq(arr, n):
    '''We insert all the array elements into unordered set.'''
    S = set();
    for i in range(n):
        S.add(arr[i]);
    ans = 0;
    for i in range(n):
        if S.__contains__(arr[i]):   
            j = arr[i]; 
            while(S.__contains__(j)):
                j += 1;
            ans = max(ans, j - arr[i]);
    return ans;
    
    
def removeDublicates(arr):
    res = []
    for i in arr:
        if i not in res:
            res.append(i)
    return res


def sniffing():
    sniff(prn=custom_action)

def analyzing():
    global packetsData
    global caughtPortDetectionHost
    while True:
        sleep(SCAN_TIME)
        clearConsole()
        dfg=packetsData.groupby(['src'])['sport'].nunique().reset_index()
        dfg.columns=['src','count']
        print(dfg)
        sus_src = []
        for index,row in dfg.iterrows():
            if int(row['count'])>UNIQUE_REQUESTS_FLAG:
                sus_src.append(row['src'])

        for i in sus_src:
            pdsus=packetsData.loc[(packetsData["src"] == i),["sport"]]['sport'].to_numpy()
            for b in range(0, len(pdsus)):
                pdsus[b] = int(pdsus[b])
            pdsus.sort()
            pdsus=removeDublicates(pdsus)
            longestSubSequence=findLongestConseqSubseq(pdsus,len(pdsus))
            if longestSubSequence>=CONSECUTIVE_PORTS_FLAG:
                caughtPortDetectionHost.append('Scanner detected. The scanner originated from host '+str(i))
            
        for x in range(len(caughtPortDetectionHost)):
            if x==0:
                print('Host that has been caught for',CONSECUTIVE_PORTS_FLAG,'consecutive ports or more in',SCAN_TIME,'seconds')
            print(caughtPortDetectionHost[x])
        packetsData = pd.DataFrame(columns=packetsData.columns)
        


if __name__ == "__main__":
    
    t1 = threading.Thread(target=sniffing)
    t2 = threading.Thread(target=analyzing)
    t1.daemon=True
    t2.daemon=True
    t1.start()
    t2.start()
    while True:
        sleep(1)
   