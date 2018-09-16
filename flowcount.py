#
# Flow Data Generation Copyright (c) 2018, All rights reserved.
# 
# If you have questions about your rights to use or distribute this
# software, please contact dcs.tamuc@gmail.com
# 
# Fri Sep 14 07:37:35 CDT 2018
# dcs.tamuc@gmail.com
#
# Tool to count entries in the IDS log (anomalous_suspicious.csv) for each priority case
#
'''
python flowcount.py -h
usage: flowcount.py [-h] [-i INPUTFILE] [-t DATESTR]

Tool to count entries in the IDS log (anomalous_suspicious.csv) for each priority case
optional arguments:
  -h, --help   (show this help message and exit)
  -i INPUTFILE, --input INPUTFILE  (input flow file path. e.g. *_result.data)
  -t DATESTR, --time DATESTR (datetime of the file. When used, -i and -o are ignored.)

e.g. 
python flowcount.py -t 2018070101
python flowcount.py -i ./20180701_anomalous_suspicious.csv


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
inputFile = ""

parser = argparse.ArgumentParser(description='Tool to combine the flow and classifier')
parser.add_argument("-i", "--input", action="store", dest="inputfile", required=False, help="input file path. e.g. *_result.data")
parser.add_argument("-t", "--time", action="store", dest="dateStr", required=False, help="datetime of the file. When used, -i and -o are ignored.")

#args = parser.parse_args([
#'-i', './20180701_anomalous_suspicious.csv',
#'-t', '2018070101'
#])
args = parser.parse_args()

if (args.inputfile):
    inputFile = args.inputfile
if (args.dateStr):
    dateStr = args.dateStr
    inputFile = "%s_anomalous_suspicious.csv" % (dateStr)
    
if not os.path.isfile(inputFile) :
    exceptstr = "input file, " + inputFile + ", does not exists"
    raise Exception(exceptstr)

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

def getPriority(label) :
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
        print("0 priority: %s, %s, %s, %s \n" % (label[1], label[2], label[3], label[4]))
    return priority

c0=0
c11=0
c12=0
c13=0
c14=0
c21=0
c22=0
c23=0
c24=0
c25=0
c26=0
c31=0
c32=0
c33=0
c34=0
c41=0
csusp=0
canom=0

f2 = open(inputFile, 'r')
csvReader = csv.reader(f2)

for row in csvReader :
    if row[0]=='anomalyID':
        continue
    tempPrior = getPriority(row)
    if tempPrior == 0:
        c0 = c0+1
    elif tempPrior == 11:
        c11 = c11+1
    elif tempPrior == 12:
        c12 = c12+1
    elif tempPrior == 13:
        c13 = c13+1
    elif tempPrior == 14:
        c14 = c14+1
    elif tempPrior == 21:
        c21 = c21+1
    elif tempPrior == 22:
        c22 = c22+1
    elif tempPrior == 23:
        c23 = c23+1
    elif tempPrior == 24:
        c24 = c24+1
    elif tempPrior == 25:
        c25 = c25+1
    elif tempPrior == 26:
        c26 = c26+1
    elif tempPrior == 31:
        c31 = c31+1
    elif tempPrior == 32:
        c32 = c32+1
    elif tempPrior == 33:
        c33 = c33+1
    elif tempPrior == 34:
        c34 = c34+1
    elif tempPrior == 41:
        c41 = c41+1
    
    if row[8] == "suspicious":
        csusp = csusp + 1
    if row[8] == "anomalous":
        canom = canom + 1

f2.close()

print(inputFile + ' : '+str(datetime.now()))
print('----------------------------------------------------------')
print('Priority          sIP  sPort  dIP  dPort\tcount')
print('priority = 41 # 4 match match match match\t'+str(c41))
print('priority = 34 # 3 match null match match\t'+str(c34))
print('priority = 33 # 3 match match match null\t'+str(c33))
print('priority = 32 # 3 null match match match\t'+str(c32))
print('priority = 31 # 3 match match null match\t'+str(c31))
print('priority = 26 # 2 match null match null\t\t'+str(c26))
print('priority = 25 # 2 null null match match\t\t'+str(c25))
print('priority = 24 # 2 null match match null\t\t'+str(c24))
print('priority = 23 # 2 match null null match\t\t'+str(c23))
print('priority = 22 # 2 match match null null\t\t'+str(c22))
print('priority = 21 # 2 null match null match\t\t'+str(c21))
print('priority = 14 # 1 null null match null\t\t'+str(c14))
print('priority = 13 # 1 match null null null\t\t'+str(c13))
print('priority = 12 # 1 null null null match\t\t'+str(c12))
print('priority = 11 # 1 null match null null\t\t'+str(c11))
print('priority = 0  # '+str(c0))
print('suspicious  # '+str(csusp))
print('anomalous  # '+str(canom))
