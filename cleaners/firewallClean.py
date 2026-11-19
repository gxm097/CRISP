import argparse
import pandas as pd
from pathlib import Path
import re
import csv
 
ROOT = Path(__file__).resolve().parents[1]
inputPath = ROOT / "inputs"
outputPath = ROOT / "tmp"
outputPath.mkdir(exist_ok=True)
 
inputFile = inputPath / "Firewall Inventory Example.csv"
outputFile = outputPath / (inputFile.stem + "_inventory.sql")
 
 
def sqlValue(value):
    if value is None or pd.isna(value):
        return "NULL"
    value = str(value).strip()
    if value == "":
        return "NULL"
    return "'" + value.replace("'", "''") + "'"
 
 
def getFirewalls(inputFile, targetRow, fireList):
    # dtype=str keeps every value exactly as written instead of guessing numbers.
    df = pd.read_csv(inputFile, dtype=str)
    if pd.notna(df.iloc[targetRow, 8]):
        fireList.append(targetRow)
 
 
def getControllerCount(fireRow, df):
    rawCell = str(df.iloc[fireRow, 7]).strip()
    numList = re.findall(r"\((\d+)\)", rawCell)
    if len(numList) < 2:
        return 0, 0
    return int(numList[0]), int(numList[1])
 
 
def getSwitchAndAPList(fireRowNum, df):
    apCount, swCount = getControllerCount(fireRowNum, df)
    apRowList = []
    swRowList = []
 
    if len(df) > fireRowNum + 1 and str(df.iloc[fireRowNum + 1, 0]).strip() == "FSW":
        for i in range(swCount):
            swRowList.append(fireRowNum + 2 + i)
 
    if len(df) > fireRowNum + 2 + swCount and str(df.iloc[fireRowNum + 2 + swCount, 0]).strip() == "FAP":
        for x in range(apCount):
            apRowList.append(fireRowNum + 3 + swCount + x)
 
    return apRowList, swRowList
 
 
def cleanFirmware(rawFirmware, deviceType):
    firmware = str(rawFirmware or "")
    if deviceType == "switch":
        match = re.search(r"v([\d.]+)-build(\d+)", firmware)
        if match:
            return match.group(1), match.group(2)
    elif deviceType == "firewall":
        match = re.search(r"FortiGate\s+([\d.]+),build(\d+)", firmware)
        if match:
            return match.group(1), match.group(2)
    elif deviceType == "ap":
        match = re.search(r"v([\d.]+)-build(\d+)", firmware)
        if match:
            return match.group(1), match.group(2)
    return None, None
 
 
def buildInsert(assetTypeId, assetName, vendor, product, version, build, hostname, publicFacing):
    return (
        "INSERT INTO InventoryAsset "
        "(OrganizationID, AssetTypeID, AssetName, Vendor, Product, Version, Build, Hostname, PublicFacing, Status) "
        f"VALUES (1, {assetTypeId}, {sqlValue(assetName)}, {sqlValue(vendor)}, {sqlValue(product)}, {sqlValue(version)}, {sqlValue(build)}, {sqlValue(hostname)}, {str(publicFacing).upper()}, 'Active');"
    )
 
 
def cleanWhiteSpace(inputFile):
    cleanFileOutputPath = outputPath / (inputFile.stem + "_cleaned.csv")
    with open(inputFile, mode="r", newline="", encoding="utf-8") as infile:
        reader = csv.reader(infile)
        cleaned_rows = []
        for row in reader:
            trimmed_row = [cell.strip() for cell in row]
            if any(trimmed_row):
                cleaned_rows.append(trimmed_row)
 
    with open(cleanFileOutputPath, mode="w", newline="", encoding="utf-8") as outfile:
        writer = csv.writer(outfile)
        writer.writerows(cleaned_rows)
    return cleanFileOutputPath
 
 
def main():
    parser = argparse.ArgumentParser(description="Clean a firewall inventory CSV file.")
    parser.add_argument("--input", type=Path, help="uploaded firewall CSV file")
    parser.add_argument("--output", type=Path, help="generated inventory SQL file")
    args = parser.parse_args()

    sourceFile = args.input if args.input else inputFile
    targetFile = args.output if args.output else outputFile
    targetFile.parent.mkdir(parents=True, exist_ok=True)

    cleanFile = cleanWhiteSpace(sourceFile)
    df = pd.read_csv(cleanFile, dtype=str)
    sqlLines = []
    fireRowList = []

    for rows in range(len(df)):
        getFirewalls(cleanFile, rows, fireRowList)

    for fireRow in fireRowList:
        hostName = df.iloc[fireRow, 3]
        firewallProduct = df.iloc[fireRow, 4]
        version, build = cleanFirmware(df.iloc[fireRow, 10], "firewall")
        sqlLines.append(buildInsert(1, df.iloc[fireRow, 0], "Fortinet", firewallProduct, version, build, hostName, True))

        apRowList, swRowList = getSwitchAndAPList(fireRow, df)
        for swRow in swRowList:
            swName = df.iloc[swRow, 0]
            swProduct = df.iloc[swRow, 4]
            swVersion, swBuild = cleanFirmware(df.iloc[swRow, 10], "switch")
            sqlLines.append(buildInsert(3, swName, "Fortinet", swProduct, swVersion, swBuild, hostName, False))

        for apRow in apRowList:
            apName = df.iloc[apRow, 0]
            apProduct = df.iloc[apRow, 4]
            apVersion, apBuild = cleanFirmware(df.iloc[apRow, 10], "ap")
            sqlLines.append(buildInsert(4, apName, "Fortinet", apProduct, apVersion, apBuild, hostName, False))

    with open(targetFile, mode="w", encoding="utf-8") as file:
        file.write("\n".join(sqlLines) + "\n")

    print("output written to: ", targetFile)


if __name__ == "__main__":
    main()
