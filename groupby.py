from ast import While
from multiprocessing import Process
import string
import sys
from collections import Counter
from time import sleep, time
from scapy.all import sniff
import pandas as pd
import logging
import threading
import time
import os

table = {
      "src":['1','1','1','1','1','1','1','1','2','2','2','2','2','1','1'],
    "sport":['1','7','3','4','111','6','2','8','2','4','4','2','1','5','5']
}

def removeDublicates(arr):
    res = []
    for i in arr:
        if i not in res:
            res.append(i)
    return res

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
    
    
df=pd.DataFrame(table)
dfg=df.groupby(['src'])['sport'].nunique().reset_index()
dfg.columns=['src','count']
print(df)
print(dfg)


UNIQUE_REQUESTS_FLAG=5
CONSECUTIVE_PORTS_FLAG=5
sus_src = []
for index, row in dfg.iterrows():
    if int(row['count'])>UNIQUE_REQUESTS_FLAG:
        sus_src.append(row['src'])

for i in sus_src:
    
    pdsus=df.loc[(df["src"] == i),["sport"]]['sport'].to_numpy()
    for i in range(0, len(pdsus)):
        pdsus[i] = int(pdsus[i])
    pdsus=removeDublicates(pdsus)
    pdsus.sort()
    print(pdsus)
    print(findLongestConseqSubseq(pdsus,len(pdsus)))


