# Tool to combine the flow and classifier
# Caitlin Sim <caitlinsim@gmail.com>
# Sep 15, 2018
#
'''
python flowlabelling.py -h
usage: flowlabelling.py [-h] [-i INPUTFILE] [-o OUTPUTDIR] [-t DATESTR]

Tool to split the flow files in timed order
optional arguments:
  -h, --help   (show this help message and exit)
  -i INPUTFILE, --input INPUTFILE  (input flow file path. e.g. *_result.data)
  -o OUTPUTDIR, --output OUTPUTDIR (output directory path)
  -t DATESTR, --time DATESTR (datetime of the file. When used, -i and -o are ignored.)
  --sec  (flow times in seconds, rather than milliseconds. default False.)

e.g. 
python flowlabelling.py -t 2018070101
python flowlabelling.py -t 2018070101 --sec
python flowlabelling.py -i ./2018070101_result.data
python flowlabelling.py -i ./2018070101_result.data -o output5


'''
import sys
import os
import csv
from datetime import datetime
from numpy import *
import numpy
import pandas as pd
import matplotlib.pyplot as plt
import argparse

dateStr = ""
flowFile = ""
resultDir = ""
csvFile = ""
timesec=False

parser = argparse.ArgumentParser(description='Tool to combine the flow and classifier')
parser.add_argument("-i", "--input", action="store", dest="inputfile", required=False, help="input file path. e.g. *_result.data")
parser.add_argument("-c", "--classifier", action="store", dest="classifier", required=False, help="input classifier file path. e.g. *_anomalous_suspicious.csv")
parser.add_argument("-o", "--output", action="store", dest="outputDir", required=False, help="output directory path")
parser.add_argument("-t", "--time", action="store", dest="dateStr", required=False, help="datetime of the file. When used, -i and -o are ignored.")
parser.add_argument("--sec", action="store_true", dest="timesec", required=False, help="flow times in seconds, rather than millisesconds. default False.")

#args = parser.parse_args([
##'-i', './2018070101_result.data',
##'-o', './2018070101_result',
#'-t', '2018070101',
##'-t', '2018070101'
#'--sec'
#])
args = parser.parse_args()

if (args.inputfile):
    flowFile = args.inputfile
if (args.classifier):
    csvFile = args.classifier
if (args.outputDir):
    resultDir = args.outputDir
if (args.dateStr):
    dateStr = args.dateStr
    flowFile = "%s_result.data" % (dateStr)
    csvFile = "%s_anomalous_suspicious.csv" % (dateStr)
if (args.timesec):
    timesec = True
    
if (len(dateStr) ==0):
    dateStr=str(datetime.now().strftime('%Y%m%d%H%M'))
if (len(resultDir) ==0):
    resultDir = "./%s_result" % (dateStr)

if not os.path.isfile(flowFile) :
    exceptstr = "input flow file, " + flowFile + ", does not exists"
    raise Exception(exceptstr)
if not os.path.isfile(csvFile) :
    exceptstr = "input classifier file, " + csvFile + ", does not exists"
    raise Exception(exceptstr)
if os.path.isdir(resultDir):
    exceptstr = "outputDir, " + resultDir + ", exists"
    raise Exception(exceptstr)
else:
    os.makedirs(resultDir)

resultCsvFile = "./%s/%s_mawilab_flow.csv" % (resultDir,dateStr)

python3 = True
if sys.version_info[0] < 3:
    python3=False
    
cntHTTP = 0
cntMultiPoint = 0
cntAlpha = 0
cntIPv6 = 0
cntPortScan = 0
cntNetworkScan = 0
cntDos = 0
cntOther = 0
cntUnknown = 0

cntNormal = 0
cntSuspicious = 0
cntAnomalous = 0

cntTotalFlow = 0
cntTotalPacket = 0
cntTotalByte = 0
cntSuspiciousPacket = 0
cntAnomalousPacket = 0
cntAnomalousByte = 0
cntSuspiciousByte = 0
cntNormalPacket = 0
cntNormalByte = 0

# 14 : Total Packets, 
# 15 : Total Bytes, 
# 16: Suspicious Packets, 
# 17 : Suspicious Bytes, 
# 18 : Anomalous Packets, 
# 19 : Anomlaous Bytes, 
# 20 : Normal Packets, 
# 21 : Normal Bytes
sec5 = zeros([int((24*60*60)/5), 22])
sec15 = zeros([int((24*60*60)/15), 22])
sec30 = zeros([int((24*60*60)/30), 22])

def getCount(t_time, t_col):
    global sec5
    global sec15
    global sec30
    t_row_5 = int(t_time / 5)
    t_row_15 = int(t_time / 15)
    t_row_30 = int(t_time / 30)
    
    sec5[t_row_5, t_col] = sec5[t_row_5, t_col] + 1
    sec15[t_row_15, t_col] = sec15[t_row_15, t_col] + 1
    sec30[t_row_30, t_col] = sec30[t_row_30, t_col] + 1
        
def getCountAndSum(t_time, t_col, p_col, p_size, b_col, b_size):
    global sec5
    global sec15
    global sec30
    t_row_5 = int(t_time / 5)
    t_row_15 = int(t_time / 15)
    t_row_30 = int(t_time / 30)
    
    sec5[t_row_5, t_col] = sec5[t_row_5, t_col] + 1
    sec15[t_row_15, t_col] = sec15[t_row_15, t_col] + 1
    sec30[t_row_30, t_col] = sec30[t_row_30, t_col] + 1
    
    sec5[t_row_5, p_col] = sec5[t_row_5, p_col] + p_size
    sec15[t_row_15, p_col] = sec15[t_row_15, p_col] + p_size
    sec30[t_row_30, p_col] = sec30[t_row_30, p_col] + p_size
    
    sec5[t_row_5, b_col] = sec5[t_row_5, b_col] + b_size
    sec15[t_row_15, b_col] = sec15[t_row_15, b_col] + b_size
    sec30[t_row_30, b_col] = sec30[t_row_30, b_col] + b_size

def getLabel(taxonomy, t_time):
    label = ''
    global cntHTTP
    global cntMultiPoint
    global cntAlpha
    global cntIPv6
    global cntPortScan
    global cntNetworkScan
    global cntDos
    global cntOther
    global cntUnknown

    if taxonomy.startswith('alphflHTTP') or taxonomy.startswith('ptmpHTTP') or taxonomy.startswith('mptpHTTP') or taxonomy.startswith('ptmplaHTTP') or taxonomy.startswith('mptplaHTTP') :
        label = 'HTTP'
        cntHTTP = cntHTTP + 1
        getCount(t_time, 5)
    elif taxonomy.startswith('ptmp') or taxonomy.startswith('mptp') or taxonomy.startswith('mptmp') :
        label = 'Multi Points'
        cntMultiPoint = cntMultiPoint + 1
        getCount(t_time, 6)
    elif taxonomy.startswith('alphfl') or taxonomy.startswith('malphfl') or taxonomy.startswith('salphfl') or taxonomy.startswith('point_to_point') or taxonomy.startswith('heavy_hitter') :
        label = 'Alpha flow'
        cntAlpha = cntAlpha + 1
        getCount(t_time, 7)
    elif taxonomy.startswith('ipv4gretun') or taxonomy.startswith('ipv46tun') :
        label = 'IPv6 tunneling'
        cntIPv6 = cntIPv6 + 1
        getCount(t_time, 8)
    elif taxonomy.startswith('posca') or taxonomy.startswith('ptpposca') :
        label = 'Port scan'
        cntPortScan = cntPortScan + 1
        getCount(t_time, 9)
    elif taxonomy.startswith('ntscIC') or taxonomy.startswith('dntscIC') : #ICMP
        label = 'Network scan'
        cntNetworkScan = cntNetworkScan + 1
        getCount(t_time, 10)
    elif taxonomy.startswith('ntscUDP') or taxonomy.startswith('ptpposcaUDP') : # UDP
        label = 'Network scan'
        cntNetworkScan = cntNetworkScan + 1
        getCount(t_time, 10)
    elif taxonomy.startswith('ntscACK') or taxonomy.startswith('ntscSYN') or taxonomy.startswith('sntscSYN') or taxonomy.startswith('ntscTCP') or taxonomy.startswith('ntscnull') or taxonomy.startswith('ntscXmas') or taxonomy.startswith('ntscFIN') or taxonomy.startswith('dntscSYN') : # TCP
        label = 'Network scan'
        cntNetworkScan = cntNetworkScan + 1
        getCount(t_time, 10)
    elif taxonomy.startswith('DoS') or taxonomy.startswith('distributed_dos') or taxonomy.startswith('ptpDoS') or taxonomy.startswith('sptpDoS') or taxonomy.startswith('DDoS') or taxonomy.startswith('rflat') :
        label = 'DoS'
        cntDos = cntDos + 1
        getCount(t_time, 11)
    elif taxonomy.startswith('ttl_error') or taxonomy.startswith('hostout') or taxonomy.startswith('netout') or taxonomy.startswith('icmp_error') :
        label = 'other'
        cntOther = cntOther + 1
        getCount(t_time, 12)
    elif taxonomy.startswith('unk') or taxonomy.startswith('empty') :
        label = 'Unknown'
        cntUnknown = cntUnknown + 1
        getCount(t_time, 13)
    else :
        print("label exception : %s \n" % (taxonomy))

    return label

def getPriority(label, sip, sport, dip, dport) :
    priority = 0
    '''
    label[1]=sip
    label[2]=sport
    label[3]=dip
    label[4]=dport
    
    # priorities in dip > sip > dport > sport
    Priority            sIP  sPort  dIP  dPort
    priority = 41   # 4 match match match match
    priority = 34   # 3 match null match match
    priority = 33   # 3 match match match null
    priority = 32   # 3 null match match match
    priority = 31   # 3 match match null match
    priority = 26   # 2 match null match null
    priority = 25   # 2 null null match match
    priority = 24   # 2 null match match null
    priority = 23   # 2 match null null match
    priority = 22   # 2 match match null null
    priority = 21   # 2 null match null match
    priority = 14   # 1 null null match null
    priority = 13   # 1 match null null null
    priority = 12   # 1 null null null match
    priority = 11   # 1 null match null null
    '''
    
    if label[1] != "" and label[2] != "" and label[3] != "" and label[4] != "" :
        priority = 41   # 4 match match match match
    elif label[1] != "" and label[2] == "" and label[3] != "" and label[4] != "" :
        priority = 34   # 3 match null match match
    elif label[1] != "" and label[2] != "" and label[3] != "" and label[4] == "" :
        priority = 33   # 3 match match match null
    elif label[1] == "" and label[2] != "" and label[3] != "" and label[4] != "" :
        priority = 32   # 3 null match match match
    elif label[1] != "" and label[2] != "" and label[3] == "" and label[4] != "" :
        priority = 31   # 3 match match null match
    elif label[1] != "" and label[2] == "" and label[3] != "" and label[4] == "" :
        priority = 26   # 2 match null match null
    elif label[3] != "" and label[4] != "" :
        priority = 25   # 2 null null match match
    elif label[2] != "" and label[3] != "" :
        priority = 24   # 2 null match match null
    elif label[1] != "" and label[4] != "" :
        priority = 23   # 2 match null null match
    elif label[1] != "" and label[2] != "":
        priority = 22   # 2 match match null null
    elif label[2] != "" and label[4] != "" :
        priority = 21   # 2 null match null match
    elif label[3] != "":
        priority = 14   # 1 null null match null
    elif label[1] != "":
        priority = 13   # 1 match null null null
    elif label[4] != "" :
        priority = 12   # 1 null null null match
    elif label[2] != "" :
        priority = 11   # 1 null match null null
    else :
        priority = 0
        print("0 priority: %s=%s, %s=%s, %s=%s, %s=%s \n" % (sip, label[1], sport, label[2], dip, label[3], dport, label[4]))
    return priority

def writeStatistics(numsec, sec5):
    # 5 sec csv
    global resultDir
    global dateStr
    index = 0
    fileName = "./%s/%s_sec%d.csv" % (resultDir,dateStr,numsec)
    filemin1 = open(fileName, 'a')
    filemin1.write('Time,Total Flows,Total Packets,Total Bytes,Anomal Flows,Suspicious Flows,Suspicious Packets,Suspicious Bytes,Anomalous Flows,Anomalous Packets,Anomalous Bytes,Normal Flows,Normal Packets,Normal Bytes'
                   'HTTP,Multi Points,Alpha,IPv6 tunneling,Port Scan,Network Scan,Dos,Other,Unknown\n')
    while index < (24*60*60)/numsec:
        if(sec5[index,0] > 0):
            temphour = index * numsec / 60 / 60
            tempmin = (index * numsec - int(temphour) * 3600) / 60
            tempsec = index * numsec - int(temphour) * 3600 - int(tempmin) * 60
            writestr = "%d:%d:%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d" % (
                temphour, tempmin, tempsec, sec5[index, 0], sec5[index, 14], sec5[index, 15], sec5[index, 1],
                sec5[index, 2], sec5[index, 16], sec5[index, 17], sec5[index, 3],
                sec5[index, 18], sec5[index, 19], sec5[index, 4], sec5[index, 20], sec5[index, 21], sec5[index, 5],
                sec5[index, 6], sec5[index, 7], sec5[index, 8], sec5[index, 9],
                sec5[index, 10], sec5[index, 11], sec5[index, 12], sec5[index, 13])
            filemin1.write(writestr)
            filemin1.write('\n')

        index = index + 1
        
    filemin1.close()
    
print('start : '+str(datetime.now()))

f3=open(resultCsvFile, 'a')
f3.write('sIP,dIP,sPort,dPort,proto,packets,bytes,flags,'
         'sTime,durat,eTime,sen,in,out,nhIP,sType,dType,senClass,typeFlow,iType,'
         'iCode,initialF,sessionF,attribut,appli,'
         'class,taxonomy,label,heuristic,distance,nbDetectors')
f3.write('\n')


f1 = open(flowFile, 'r')

rstr = f1.readline()
rstr = f1.readline()
rstr = f1.readline()
rstr = f1.readline()

anomalCnt = 0

f2 = open(csvFile, 'r')
csvReader = csv.reader(f2)

#csvReader = pd.read_csv(csvFile, sep=',')
csvinfo = []
for row in csvReader :
    csvinfo.append(row)

while rstr:
    fieldsValue = rstr.split('|')

    cnt = 0
    prior = 0
    taxo = ""
    heuri = ""
    dist = ""
    detect = ""

    for row in csvinfo :
        if row[0]=='anomalyID':
            continue

        if (row[1]==fieldsValue[0].strip() or row[1]=="") and (row[2]==fieldsValue[2].strip() or row[2]=="") and (row[3]==fieldsValue[1].strip() or row[3]=="") and (row[4]==fieldsValue[3].strip() or row[4]=="") :
            cnt = cnt + 1
            #tempPrior = getPriority(row[1],row[2],row[3],row[4])
            tempPrior = getPriority(row, fieldsValue[0].strip(), fieldsValue[2].strip(), fieldsValue[1].strip(), fieldsValue[3].strip())
            if prior < tempPrior :
                taxo = row[5]
                heuri = row[6]
                dist = row[7]
                detect = row[8]
                prior = tempPrior
            #break

#    if cnt > 1:
#	    print('multiple match : %d' % cnt)

    cntTotalFlow = cntTotalFlow + 1
    cntTotalPacket = cntTotalPacket + int(fieldsValue[5].strip())
    cntTotalByte = cntTotalByte + int(fieldsValue[6].strip())

    if timesec:
        time = datetime.strptime(fieldsValue[10].strip(), "%Y/%m/%dT%H:%M:%S")
    else:
        time = datetime.strptime(fieldsValue[10].strip(), "%Y/%m/%dT%H:%M:%S.%f")
    timemin = int(time.hour) * 3600 + int(time.minute) * 60 + int(time.second)

    getCountAndSum(timemin, 0, 14, int(fieldsValue[5].strip()), 15, int(fieldsValue[6].strip()))

    if cnt :
        labelStr = getLabel(taxo, timemin)
        outStr = "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,anomaly,%s,%s,%s,%s,%s" % (
        fieldsValue[0].strip(), fieldsValue[1].strip(), fieldsValue[2].strip(), fieldsValue[3].strip(),
        fieldsValue[4].strip(), fieldsValue[5].strip(), fieldsValue[6].strip(), fieldsValue[7].strip(),
        fieldsValue[8].strip(), fieldsValue[9].strip(), fieldsValue[10].strip(), fieldsValue[11].strip(),
        fieldsValue[12].strip(), fieldsValue[13].strip(), fieldsValue[14].strip(), fieldsValue[15].strip(),
        fieldsValue[16].strip(), fieldsValue[17].strip(), fieldsValue[18].strip(), fieldsValue[19].strip(),
        fieldsValue[20].strip(), fieldsValue[21].strip(), fieldsValue[22].strip(), fieldsValue[23].strip(), fieldsValue[24].strip(), 
        taxo, labelStr, heuri, dist, detect)
        anomalCnt = anomalCnt + 1

        if(detect == 'suspicious') :
            cntSuspicious = cntSuspicious + 1
            cntSuspiciousPacket = cntSuspiciousPacket + int(fieldsValue[5].strip())
            cntSuspiciousByte = cntSuspiciousByte + int(fieldsValue[6].strip())
            getCountAndSum(timemin, 2, 16, int(fieldsValue[5].strip()), 17, int(fieldsValue[6].strip()))
            
        elif(detect == 'anomalous') :
            cntAnomalous = cntAnomalous + 1
            cntAnomalousPacket = cntAnomalousPacket + int(fieldsValue[5].strip())
            cntAnomalousByte = cntAnomalousByte + int(fieldsValue[6].strip())
            getCountAndSum(timemin, 3, 18, int(fieldsValue[5].strip()), 19, int(fieldsValue[6].strip()))

        getCount(timemin, 1)
    else:
        outStr = "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,normal" % (
        fieldsValue[0].strip(), fieldsValue[1].strip(), fieldsValue[2].strip(), fieldsValue[3].strip(),
        fieldsValue[4].strip(), fieldsValue[5].strip(), fieldsValue[6].strip(), fieldsValue[7].strip(),
        fieldsValue[8].strip(), fieldsValue[9].strip(), fieldsValue[10].strip(), fieldsValue[11].strip(),
        fieldsValue[12].strip(), fieldsValue[13].strip(), fieldsValue[14].strip(), fieldsValue[15].strip(),
        fieldsValue[16].strip(), fieldsValue[17].strip(), fieldsValue[18].strip(), fieldsValue[19].strip(),
        fieldsValue[20].strip(), fieldsValue[21].strip(), fieldsValue[22].strip(), fieldsValue[23].strip(), fieldsValue[24].strip())
        cntNormal = cntNormal + 1
        cntNormalPacket = cntNormalPacket + int(fieldsValue[5].strip())
        cntNormalByte = cntNormalByte + int(fieldsValue[6].strip())
        #print(fieldsValue[0], fieldsValue[1])
        getCountAndSum(timemin, 4, 20, int(fieldsValue[5].strip()), 21, int(fieldsValue[6].strip()))

    f3.write(outStr)
    f3.write('\n')
    rstr = f1.readline()


f2.close()
f1.close()
f3.close()

print('flowFile_result_data: '+str(datetime.now()))

# 5 sec csv
writeStatistics(5, sec5)
print('5_sec_csv: '+str(datetime.now()))

# 15 sec csv
writeStatistics(15, sec15)
print('15_sec_csv: '+str(datetime.now()))

# 30 sec csv
writeStatistics(30, sec15)
print('30_sec_csv: '+str(datetime.now()))

fileName = "./%s/%s_statistics.csv" % (resultDir,dateStr)
fileStatistics = open(fileName, 'a')

fileStatistics.write('Total Flow Count,Anormaly Count,Total Packets,Total Bytes\n')
fileStatistics.write("%d,%d,%d,%d\n\n" % (cntTotalFlow,anomalCnt,cntTotalFlow,cntTotalByte))
fileStatistics.write('Suspicious Flow,Suspicious Packets,Suspicious Bytes,Anomalous Flow,Anomlaous Pakcets,Anomalous Bytes,Normal Flow,Normal Pakcets,Normal Bytes\n')
fileStatistics.write("%d,%d,%d,%d,%d,%d,%d,%d,%d\n\n" % (cntSuspicious,cntSuspiciousPacket,cntSuspiciousByte,cntAnomalous,cntAnomalousPacket,cntAnomalousByte,cntNormal,cntNormalPacket,cntNormalByte))
fileStatistics.write('HTTP,Multi Points,Alpha,IPv6 tunneling,Port Scan,Network Scan,Dos,Other,Unknown\n')
fileStatistics.write("%d,%d,%d,%d,%d,%d,%d,%d,%d\n\n" % (cntHTTP,cntMultiPoint,cntAlpha,cntIPv6,cntPortScan,cntNetworkScan,cntDos,cntOther,cntUnknown))

fileStatistics.close()

print('finish : ' + str(datetime.now()))

print('total Flow Conunt : %d, anormal count : %d' % (cntTotalFlow,anomalCnt))
print('suspicious : %d, anomalous : %d, normal : %d' % (cntSuspicious,cntAnomalous,cntNormal))
print('HTTP : %d, Multi Points : %d, Alpha : %d, IPv6 tunneling : %d, Port Scan : %d, Network Scan : %d, Dos : %d, Other : %d, Unknown : %d' % (cntHTTP,cntMultiPoint,cntAlpha,cntIPv6,cntPortScan,cntNetworkScan,cntDos,cntOther,cntUnknown))

# Plotting
labels1 = ['suspicious', 'anomalous', 'normal']
ratio1 = [cntSuspicious,cntAnomalous,cntNormal]

labels2 = ['HTTP', 'Multi Points', 'Alpha', 'IPv6 Tunneling', 'Port Scan', 'Network Scan', 'Dos', 'Other', 'Unknown']
ratio2 = [cntHTTP,cntMultiPoint,cntAlpha,cntIPv6,cntPortScan,cntNetworkScan,cntDos,cntOther,cntUnknown]

plt.pie(ratio1, labels=labels1, shadow=True, startangle=90)
#plt.show()
plt.savefig("ratio1-"+str(dateStr)+".pdf", format='pdf')

plt.pie(ratio2, labels=labels2, shadow=True, startangle=90)
#plt.show()
plt.savefig("ratio2-"+str(dateStr)+".pdf", format='pdf')

print('now : ' + str(datetime.now()))
