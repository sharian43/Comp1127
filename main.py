import math
import os
import random
import re
import sys

'''
Group Information:

Member 1: sharian Johnson
Member 2: Ashleigh McLean

'''

#1
def makePacket(srcIP, dstIP, length, prt, sp, dp, sqn, pld):
    return ("PK",srcIP, dstIP,[length, prt,[sp, dp],sqn, pld])

def getPacketSrc(pkt):
    return pkt[1]
    
def getPacketDst(pkt):
    return pkt[2]
    
def getPacketDetails(pkt):
    return pkt[3]
    
def isPacket(pkt):
    return type(pkt)==tuple and pkt[0]=="PK" and type(pkt[1])==str

def isEmptyPkt(pkt):
    return pkt[0]==[]

#2
def getLength(pkt):
    return pkt[3][0]

def getProtocol(pkt):
    return pkt[3][1]

def getSrcPort(pkt):
    return pkt[3][2][0]

def getDstPort(pkt):
    return pkt[3][2][1]

def getSqn(pkt):
    return pkt[3][3]

def getPayloadSize(pkt):
    return pkt[3][-1]

#3
def flowAverage(pkt_list):
    def foldr(com, base, lst):
        if lst == []:
              return base
        else:
             return com(lst[0],foldr(com, base, lst[1:]))
    pLst_len = len(pkt_list)
    
    pLS_lst = [getPayloadSize(x) for x in pkt_list]
    
    pLsSum = foldr(lambda x,y:x+y, 0, pLS_lst)
    avg = pLsSum/pLst_len
    
    aboveAvg = [x for x in pkt_list if getPayloadSize(x) > avg]
    return aboveAvg

def suspPort(pkt):
    return getSrcPort(pkt)>500 or getDstPort(pkt)>500

def suspProto(pkt):
    ProtocolList = ["HTTP","SMTP","UDP","TCP","DHCP"]
    return getProtocol(pkt) not in ProtocolList

def ipBlacklist(pkt):
    IpBlackList = ["213.217.236.184","149.88.83.47","223.70.250.146","169.51.6.136","229.223.169.245"]
    return getPacketSrc(pkt) in IpBlackList 

#4
def calScore(pkt):
    pkt_score = 0
    def foldr(com, base, lst):
        if lst == []:
              return base
        else:
             return com(lst[0],foldr(com, base, lst[1:]))
    
    def avgADT(pkt_list):
        pLst_len = len(pkt_list)
        pLS_lst = [getPayloadSize(x) for x in pkt_list]
        
        pLsSum = foldr(lambda x,y: x+y, 0, pLS_lst)
        avg = pLsSum/pLst_len
        return avg
    
    average = avgADT(pkt_list)
    
    if getPayloadSize(pkt) > average:
        pkt_score +=3.56
        
    if  suspPort(pkt) == True:
        pkt_score +=1.45

    if suspProto(pkt) == True:
        pkt_score +=2.74
        
    if  ipBlacklist(pkt) == True:
        pkt_score +=10
        
    if pkt_score == 0:
        return pkt_score
    else:
        return float(pkt_score)

def makeScore(pkt_list):
    pkt_scorelst = []
    for i in pkt_list:
        score = calScore(i)
        pkt_scorelst.append((i,score))
    return ["SCORE",pkt_scorelst]   

def addPacket(ScoreList, pkt):
    if isPacket(pkt) == True:
        score = calScore(pkt)
        ScoreList[1].append((pkt,score))
    else:
        raise TypeError ("Not a packet")
    
def getSuspPkts(ScoreList):
    sus = []
    for i in ScoreList[1]:
        if i[1] > 5.00:
            sus.append(i[0])
    return sus

def getRegulPkts(ScoreList):
    reg = []
    for i in ScoreList[1]:
        if i[1] < 5.00:
            reg.append(i[0])
    return reg

def isScore(ScoreList):
    return type(ScoreList)==list and ScoreList[0]=="SCORE" and type(ScoreList[1])==list
    
def isEmptyScore(ScoreList):
    return  ScoreList[1] == []

#5
def makePacketQueue():
    return ("PQ", [])

def contentsQ(q):
    return q[1]

def frontPacketQ(q):
    return contentsQ(q)[0]

def addToPacketQ(pkt,q):
    if isPacketQ(q):
        p = get_pos(pkt, contentsQ(q))
        contentsQ(q).insert(p, pkt)
    else: 
        raise TypeError("not a packet")

def get_pos(pkt,lst):
    if (lst == []):
        return 0
    elif getSqn(pkt) < getSqn(lst[0]):
        return 0 + get_pos(pkt,[])
    else:
        return 1 + get_pos(pkt,lst[1:])
            
def removeFromPacketQ(q):
    if not isPacketQ(q):
        raise TypeError("not a packet")
    elif isEmptPacketQ(q):
        raise IndexError("packet is empty")
    else:
        contentsQ(q).pop(0)
        
def isPacketQ(q):
    return type(q)==tuple and type(contentsQ(q))==list and q[0]=="PQ" and len(q)==2

def isEmptPacketQ(q):
    return contentsQ(q)==[]

#6
def makePacketStack():
    return ("PS", [])

def contentsStack(stk):
    return stk[1]

def topProjectStack (stk):
    return contentsStack(stk)[0]

def pushProjectStack(pkt,stk):
    if isPKstack(stk):
        contentsStack(stk).append(pkt)
    else:
        raise TypeError("not a stack")

def popPickupStack(stk):
    if not isPKstack(stk):
        raise TypeError("not a stack")
    elif isEmptyPKStack(stk):
        raise IndexError("stack is empty")
    else:
        contentsStack(stk).pop(-1)

def isPKstack(stk):
    return type(stk)==tuple and len(stk)==2 and stk[0]=="PS" and  type(contentsStack(stk))==list  

def isEmptyPKStack(stk):
    return contentsStack(stk)==[]

#7
def sortPackets(scoreList,stack,queue):
    suslst = getSuspPkts(scoreList)
    reglst = getRegulPkts(scoreList)
    
    for i in suslst:
        pushProjectStack(i,stack)
        
    for j in reglst:
        addToPacketQ(j, queue)

#8
def analysePackets(packet_List):
    p_list = [makePacket(pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5], pkt[6], pkt[7]) for pkt in packet_List]
    
    scoreList = makeScore(p_list)
    stacK = makePacketStack()
    qUeUe = makePacketQueue()
    sortPackets(scoreList, stacK,qUeUe)
    return qUeUe

if __name__ == '__main__':
    fptr = open(os.environ['OUTPUT_PATH'], 'w')

    first_multiple_input = input().rstrip().split()
    
    srcIP = str(first_multiple_input[0])
    dstIP = str(first_multiple_input[1])
    length = int(first_multiple_input[2])
    prt = str(first_multiple_input[3])
    sp = int(first_multiple_input[4])
    dp = int(first_multiple_input[5])
    sqn = int(first_multiple_input[6])
    pld = int(first_multiple_input[7])
    
    ProtocolList = ["HTTPS","SMTP","UDP","TCP","DHCP","IRC"]
    IpBlackList = ["213.217.236.184","149.88.83.47","223.70.250.146","169.51.6.136","229.223.169.245"]
    
    packet_List = [(srcIP, dstIP, length, prt, sp, dp, sqn, pld),\
              ("111.202.230.44","62.82.29.190",31,"HTTP",80,20,1562436,338),\
              ("222.57.155.164","50.168.160.19",22,"UDP",790,5431,1662435,812),\
              ("333.230.18.207","213.217.236.184",56,"IMCP",501,5643,1762434,3138),\
              ("444.221.232.94","50.168.160.19",1003,"TCP",4657,4875,1962433,428),\
              ("555.221.232.94","50.168.160.19",236,"HTTP",7753,5724,2062432,48)]
    
    pkt = makePacket(srcIP, dstIP, length, prt, sp, dp, sqn, pld)
    pk1 = makePacket("111.202.230.44","62.82.29.190",31,"HTTP",80,20,1562436,338)
    pk2 = makePacket("222.57.155.164","50.168.160.19",22,"UDP",790,5431,1662435,812)
    pk3 = makePacket("333.230.18.207","213.217.236.184",56,"IRC",501,5643,1762434,3138)
    pk4 = makePacket("444.221.232.94","50.168.160.19",1003,"TCP",4657,4875,1962433,428)
    pk5 = makePacket("555.221.232.94","50.168.160.19",236,"TCP",7753,5724,2062432,48)
    
    pkt_list = [pkt,pk1,pk2,pk3,pk4,pk5]
    p_list = [makePacket(pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5], pkt[6], pkt[7]) for pkt in packet_List]
    
    scoreList = makeScore(p_list)
    stacK = makePacketStack()
    qUeUe = makePacketQueue()
    
    sortPackets(scoreList, stacK,qUeUe)
    
    analysePackets(packet_List)
    
    fptr.write('Forward Packets => ' + str(analysePackets(packet_List)) + '\n')
    
    fptr.close()