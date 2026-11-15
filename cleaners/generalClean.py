
import pandas as pd
from pathlib import Path
 
ROOT = Path(__file__).resolve().parents[1]
inputPath = ROOT / "inputs"
outputPath = ROOT / "tmp"
outputPath.mkdir(exist_ok=True)
 
 
def listFiles(inputPath):
    return sorted(inputPath.glob("*csv"))
 
 
def getFileName(filePath):
    return filePath.stem
 
 
def getProductName(inputFileName):
    cleanName = inputFileName.replace(".csv", "")
    if "installation" in cleanName:
        return " ".join(part for part in cleanName.split("installation")[0].split("_") if part).strip()
    return " ".join(cleanName.split("_")).strip()
 
 
def sqlValue(value):
    if value is None or pd.isna(value):
        return "NULL"
    value = str(value).strip()
    if value == "":
        return "NULL"
    return "'" + value.replace("'", "''") + "'"
 
 
def isBlank(value):
    return value is None or pd.isna(value) or str(value).strip() == ""
 
 
def loadCsv(filePath):
    # dtype=str keeps every value exactly as written (5.10 stays "5.10", not 5.1).
    df = pd.read_csv(filePath, dtype=str)
    # Drop rows that are completely empty (e.g. ",,," lines left by an Excel export).
    return df.dropna(how="all").reset_index(drop=True)
 
 
def getData(df, targetRow, product):
    deviceName = df.iloc[targetRow, 0]
    # AssetName is NOT NULL in the database, so a row with no name can't be inserted.
    if isBlank(deviceName):
        return None
 
    version = df.iloc[targetRow, 1]
    vendor = df.iloc[targetRow, 2] if len(df.columns) > 2 else None
 
    return (
        "INSERT INTO InventoryAsset "
        "(OrganizationID, AssetTypeID, AssetName, Vendor, Product, Version, Build, Hostname, PublicFacing, Status) "
        f"VALUES (1, 5, {sqlValue(deviceName)}, {sqlValue(vendor)}, {sqlValue(product)}, {sqlValue(version)}, NULL, NULL, FALSE, 'Active');"
    )
 
 
csvFiles = listFiles(inputPath)
for csvFile in csvFiles:
    file = getFileName(csvFile)
    print(file)
    outputFile = outputPath / (file + "_inventory.sql")
    df = loadCsv(csvFile)
    productName = getProductName(file)
 
    sqlLines = []
    skipped = 0
    for row in range(len(df)):
        line = getData(df, row, productName)
        if line is None:
            skipped += 1
        else:
            sqlLines.append(line)
 
    if skipped:
        print("skipped", skipped, "row(s) with no asset name")
 
    if not sqlLines:
        print("no valid rows found, no output file written")
        continue
 
    with open(outputFile, "w", encoding="utf-8") as fileHandle:
        fileHandle.write("\n".join(sqlLines) + "\n")
    print("done, output file = ", outputFile)
 