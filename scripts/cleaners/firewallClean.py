import pandas as pd
from pathlib import Path
import re
import json

inputPath = Path.home() / "Projects" / "softwareClass" / "inputs"
outputPath = Path.home() / "Projects" / "softwareClass" / "tmp"

inputFile = inputPath / 'Firewall Inventory Example.csv'




def getFirewalls(inputFile, targetRow, fireList):
    df = pd.read_csv(inputFile)
    
    if pd.notna(df.iloc[targetRow, 8]):
        fireList.append(targetRow)

def getControllerCount(fireRow, df): #0 = aps, 1 = sw
    numList = []
    rawCell = df.iloc[fireRow, 7]

    numList = re.findall(r"\((.*?)\)", rawCell)

    apCount = int(numList[0])
    swCount = int(numList[1])
    
    return apCount, swCount

def getSwitchAndAPList(fireRowNum, df):
    apCount, swCount = getControllerCount(fireRowNum, df)
    apRowList = []
    swRowList = []

    if df.iloc[fireRowNum + 2 + swCount, 0] == "    FAP":
        for x in range(apCount):
            apRow = fireRowNum + 3 + swCount + x
            apRowList.append(apRow)
    
    if df.iloc[fireRowNum + 1, 0] == "    FSW":
        for i in range(swCount):
            swRow = fireRowNum + 2 + i
            swRowList.append(swRow)

    return apRowList, swRowList

def groupToJson(FirewallRowNum, apRowList, swRowList):
    deviceTypes = ["firewall", "accessPoint", "Switch"]
    
    data = {
        "deviceType": "null",
        "name": "null",
        "hostName": "null",
        "platfom": "null",
        "firwareVersion": "null",
        "build": "null"

    }
    return

def getFirewallInfo(firewallRowNum, df):
    devieType = "firewall"
    deviceName = df.iloc[firewallRowNum, 1]
    hostName = df.iloc[firewallRowNum, 4]
    hostName = df.iloc[firewallRowNum, 4]
    platform = df.iloc[firewallRowNum, 5] #ended here

    print(df.iloc[firewallRowNum])



swRowList = []
fireRowList = []
apRowList = []
df = pd.read_csv(inputFile)
for rows in range(len(df)):
    getFirewalls(inputFile, rows, fireRowList)

i=0#for i in range(len(fireRowList)):
apRowList, swRowList = getSwitchAndAPList(fireRowList[i], df)
getFirewallInfo(fireRowList[i], df)

#getControllerCount(fireRowList, df)
