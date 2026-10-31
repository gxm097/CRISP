import pandas as pd
from pathlib import Path
import re
import json
import csv

inputPath = Path.home() / "Projects" / "softwareClass" / "inputs"
outputPath = Path.home() / "Projects" / "softwareClass" / "tmp"
inputFile = inputPath / 'Firewall Inventory Example.csv'
cleanFileName = inputFile.stem + "CLEANED.csv"
cleanFile = outputPath / cleanFileName
outputFileName = inputFile.stem + ".json"
outputFile = outputPath / outputFileName



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

    if df.iloc[fireRowNum + 2 + swCount, 0] == "FAP":
        for x in range(apCount):
            apRow = fireRowNum + 3 + swCount + x
            apRowList.append(apRow)
    
    if df.iloc[fireRowNum + 1, 0] == "FSW":
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

def cleanFirmware(rawFirmware, deviceType):
    if deviceType == "switch":
        match = re.search(r"v([\d.]+)-build(\d+)", rawFirmware)
        if match:
            version = match.group(1)
            build = match.group(2)

    elif deviceType == "firewall":
        match = re.search(r"FortiGate\s+([\d.]+),build(\d+)", rawFirmware)

        if match:    
            version = match.group(1)
            build = match.group(2)
    elif deviceType == "ap":
        match = re.search(r"v([\d.]+)-build(\d+)", rawFirmware)

        if match:
            version = match.group(1)
            build = match.group(2)

    return version, build


def infoToJsonSwAp(swRowList, apRowList, hostname, df, jsonData, inputFile):
    for i in range(len(swRowList)):
        version, build = cleanFirmware(df.iloc[swRowList[0], 10], "switch")
        data = {
                "deviceType": "switch",
                "name": df.iloc[swRowList[i], 0],
                "hostName": hostname,
                "platfom": df.iloc[swRowList[i], 4],
                "firwareVersion": version,
                "build": build,
                "fileName": str(inputFile)
            }
        jsonData.append(data)
    for x in range(len(apRowList)):
        version, build = cleanFirmware(df.iloc[swRowList[0], 10], "switch")
        data = {
                "deviceType": "ap",
                "name": df.iloc[apRowList[x], 0],
                "hostName": hostname,
                "platfom": df.iloc[apRowList[x], 4],
                "firwareVersion": version,
                "build": build,
                "fileName": str(inputFile)
            }
        jsonData.append(data)
    return

def infoToJsonFirewall(firewallRowNum, df, jsonData, inputFile):
    version, build = cleanFirmware(df.iloc[firewallRowNum, 10], "firewall")
    hostName = df.iloc[firewallRowNum, 3]
    
    data = {
        "devieType": "firewall",
        "deviceName": df.iloc[firewallRowNum, 0],
        "hostName": hostName,
        "platform": df.iloc[firewallRowNum, 4],
        "firwareVersion": version,
        "build": build,
        "fileName": str(inputFile)
    }

    jsonData.append(data)
    return hostName

def cleanWhiteSpace(inputFile): #done
    cleanFile = inputFile.stem + "CLEANED.csv"
    cleanFileOutputPath = outputPath / cleanFile

    # Read, strip whitespace, and write out
    with open(inputFile, mode="r", newline="", encoding="utf-8") as infile:
        reader = csv.reader(infile)
        cleaned_rows = []

        for row in reader:
            # Strip whitespace from each cell
            trimmed_row = [cell.strip() for cell in row]
            # Keep row if it's not completely empty
            if any(trimmed_row):
                cleaned_rows.append(trimmed_row)

    with open(cleanFileOutputPath, mode="w", newline="", encoding="utf-8") as outfile:
        writer = csv.writer(outfile)
        writer.writerows(cleaned_rows)




cleanWhiteSpace(inputFile)
swRowList = []
fireRowList = []
apRowList = []
df = pd.read_csv(cleanFile)
jsonData = []

for rows in range(len(df)):
    getFirewalls(cleanFile, rows, fireRowList)

for i in range(len(fireRowList)):
    apRowList, swRowList = getSwitchAndAPList(fireRowList[i], df)
    hostName = infoToJsonFirewall(fireRowList[i], df, jsonData, inputFile)
    infoToJsonSwAp(swRowList, apRowList, hostName, df, jsonData, inputFile)

with open(outputFile, mode="w") as file:
    json.dump(jsonData, file, indent=4)
print("output written to: ", outputFile)

