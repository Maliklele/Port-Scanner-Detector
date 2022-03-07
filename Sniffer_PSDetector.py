
from time import sleep
from scapy.all import sniff
import pandas as pd
import threading
import os

# FLAGS TO CHANGE THE BEHAVIOUR OF THE SCRIPT
UNIQUE_REQUESTS_FLAG = 15
CONSECUTIVE_PORTS_FLAG = 15
SCAN_TIME = 5
SHOW_PACKET_COUNT = False


# This command is excuted to clear the console line
def clearConsole(): return os.system(
    'cls' if os.name in ('nt', 'dos') else 'clear')


# I used pandas library to manipulate the entries, filter.. and such
packetsData = pd.DataFrame(columns=['src', 'sport'])

# This array will store the caught scanners
caughtPortDetectionHost = []

# This method will find the largest consequetive subsquence so that we catch if it's greater than 15 consequetive subsequence


def findLongestConseqSubseq(arr, n):
    '''We insert all the array elements into unordered set.'''
    S = set()
    for i in range(n):
        S.add(arr[i])
    ans = 0
    for i in range(n):
        if S.__contains__(arr[i]):
            j = arr[i]
            while(S.__contains__(j)):
                j += 1
            ans = max(ans, j - arr[i])
    return ans


# This method will remove dublicates entries in an array, I used it in my algorthim to check a uniuqe subsequnce
def removeDublicates(arr):
    res = []
    for i in arr:
        if i not in res:
            res.append(i)
    return res


# This method will be excuted in the sniffer with each packet
def custom_action(packet):
    global packetsData
    # If the packet has a src and a source port
    if hasattr(packet.payload, "src") and hasattr(packet.payload, "sport"):
        # We add that packet inside the the packetsData global variable
        packet = pd.DataFrame(
            {"src": [packet[0][1].src], "sport": [packet[0][1].sport]})
        packetsData = pd.concat([packetsData, packet])


# Start sniffing for packets (Will be excuted in a thread)
def sniffing():
    sniff(prn=custom_action)

# Start analysing the packets (Will be excuted in a thread)


def analyzing():
    global packetsData
    global caughtPortDetectionHost
    while True:
        sleep(SCAN_TIME)
        clearConsole()
        # packetsUniqueCount will
        packetsUniqueCount = packetsData.groupby(
            ['src'])['sport'].nunique().reset_index()
        packetsUniqueCount.columns = ['src', 'count']
        if SHOW_PACKET_COUNT:
            print(packetsUniqueCount)
        # Array to hold the suspected sourced that has count>=subsequnce. because if we have the count less than the specified subsequnce it we dont need to check it
        sus_src = []
        for index, row in packetsUniqueCount.iterrows():
            if int(row['count']) >= UNIQUE_REQUESTS_FLAG:
                sus_src.append(row['src'])

        # Then we go to those suspect sources and and make and array of the source ports
        # We first sort that array of ports then remove dublications
        # After that we run the logest subsequence algorthim
        # If that array has a subsequnce of the specified amount
        # We push that Source IP to the caught sources array and print them
        for i in sus_src:
            pdsus = packetsData.loc[(packetsData["src"] == i), [
                "sport"]]['sport'].to_numpy()
            for j in range(0, len(pdsus)):
                pdsus[j] = int(pdsus[j])
            pdsus.sort()
            pdsus = removeDublicates(pdsus)
            longestSubSequence = findLongestConseqSubseq(pdsus, len(pdsus))
            if longestSubSequence >= CONSECUTIVE_PORTS_FLAG:
                caughtPortDetectionHost.append(
                    'Scanner detected. The scanner originated from host '+str(i)+' with '+str(longestSubSequence)+' subsequnce')

        #Printing the detected scanners
        for x in range(len(caughtPortDetectionHost)):
            if x == 0:
                print('Host that has been caught for', CONSECUTIVE_PORTS_FLAG,
                      'consecutive ports or more in', SCAN_TIME, ' seconds')
            print(caughtPortDetectionHost[x])
        packetsData = pd.DataFrame(columns=packetsData.columns)


if __name__ == "__main__":
    #We create the threads and start them
    t1 = threading.Thread(target=sniffing)
    t2 = threading.Thread(target=analyzing)
    t1.daemon = True
    t2.daemon = True
    t1.start()
    t2.start()
    #This is so that we can terminate the program with Ctrl+C on the CMD
    while True:
        sleep(1)
