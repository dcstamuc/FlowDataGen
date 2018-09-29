#
# Flow Data Generation Copyright (c) 2018, All rights reserved.
# 
# If you have questions about your rights to use or distribute this
# software, please contact dcs.tamuc@gmail.com
# 
# Fri Sep 14 07:37:35 CDT 2018
# dcs.tamuc@gmail.com
#
# Tool to split the flow files in timed order (e.g. 5 second)
# by Caitlin S.
#
'''
python flowsplitter.py -h
usage: flowsplitter.py [-h] [-i INPUTFILE] [-o OUTPUTDIR] [-t DATESTR]
                       [-n SPLITSEC]
Tool to split the flow files in timed order
optional arguments:
  -h, --help   (show this help message and exit)
  -i INPUTFILE, --input INPUTFILE  (input flow file path. e.g. *_mawilab_flow.csv)
  -o OUTPUTDIR, --output OUTPUTDIR (output directory path)
  -t DATESTR, --time DATESTR (datetime of the file. When used, -i and -o are ignored.)
  -n SPLITSEC  (time separation in seconds. default 5 sec.)
  --sec  (flow times from rwstats in seconds, rather than milliseconds. default False.)

e.g. 
python flowsplitter.py -t 2018070101 -n 5
python flowsplitter.py -t 2018070101 -n 5 --sec
python flowsplitter.py -t 2018070101 -n 15
python flowsplitter.py -t 2018070101 -n 30
python flowsplitter.py -i ./2018070101_result/2018070101_mawilab_flow.csv -n 5
python flowsplitter.py -i ./2018070101_result/2018070101_mawilab_flow.csv -o output5 -n 5


'''
import sys
import os
import csv
from datetime import datetime
from numpy import *
import numpy
import math
import pandas as pd
import matplotlib.pyplot as plt
import argparse

#print(sys.version_info[0])

dateStr = ""
splitsec = 5
inputfile = ""
outputDir = ""
timesec=False

parser = argparse.ArgumentParser(description='Tool to split the flow files in timed order')
parser.add_argument("-i", "--input", action="store", dest="inputfile", required=False, help="input file path. e.g. *_mawilab_flow.csv")
parser.add_argument("-o", "--output", action="store", dest="outputDir", required=False, help="output directory path")
parser.add_argument("-t", "--time", action="store", dest="dateStr", required=False, help="datetime of the file. When used, -i and -o are ignored.")
parser.add_argument("-n", action="store", dest="splitsec", required=False, help="time separation in seconds. default 5 sec.")
parser.add_argument("--sec", action="store_true", dest="timesec", required=False, help="flow times from rwstats in seconds, rather than millisesconds. default False.")

#args = parser.parse_args([
#'-i', './2018070101_result/2018070101_mawilab_flow.csv',
#'-t', '2018070101',
#'-n', '5'
#'--sec'
#])
args = parser.parse_args()     # uncomment this line for general use

if (args.inputfile):
    inputfile = args.inputfile
if (args.outputDir):
    outputDir = args.outputDir
if (args.dateStr):
    dateStr = args.dateStr
    inputfile = "./%s_result/%s_mawilab_flow.csv" % (dateStr,dateStr)
if (args.splitsec):
    splitsec = int(args.splitsec)
if (args.timesec):
    timesec = True
    
if (len(dateStr) ==0):
    dateStr=str(datetime.now().strftime('%Y%m%d%H%M'))
if (len(outputDir) ==0):
    outputDir = "./%s_result_%dsec" % (dateStr,splitsec)
    
if os.path.isdir(outputDir):
    exceptstr = "outputDir, " + outputDir + ", exists"
    raise Exception(exceptstr)
else:
    os.makedirs(outputDir)

def myprint(mystr):
    print(mystr)

def timetag(timevalue):
    global timesec
    global splitsec
    if timesec:
        mytime = datetime.strptime(timevalue, "%Y/%m/%dT%H:%M:%S")
    else:
        mytime = datetime.strptime(timevalue, "%Y/%m/%dT%H:%M:%S.%f")
    timemin = int(mytime.minute) * 60 + int(mytime.second)
    mytag = math.floor(timemin/splitsec)
    return mytag
    
filetag=0
file_dict={}

f1=open(inputfile, 'r')
rstr = f1.readline()
rstr = f1.readline()

while rstr:
    fieldsValue = rstr.split(',')
    filetag = timetag(fieldsValue[8].strip())
    if filetag in file_dict:
        f3 = file_dict[filetag]
        f3.write(rstr)
    else:
        flowFile = "./%s/%s_mawilab_flow-%dsec-%d.csv" % (outputDir,dateStr,splitsec,filetag)
        #myprint(str(datetime.now()) + " : " + flowFile)
        f3 = open(flowFile, 'w')
        f3.write('sIP,dIP,sPort,dPort,pro,packets,bytes,flags,'
                 'sTime,durat,eTime,sen,in,out,nhIP,cla,type,iTy,'
                 'iCo,initialF,sessionF,attribut,appli,'
                 'status,taxonomy,category,heuristic,distance,label')
        f3.write('\n')
        f3.write(rstr)
        file_dict[filetag] = f3
                
    rstr = f1.readline()

myprint("num_files="+str(len(file_dict)))
for thisfile in file_dict:
    file_dict[thisfile].close()
    
f1.close()
myprint('Done: '+str(datetime.now()))
