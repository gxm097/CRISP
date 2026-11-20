import argparse
import sys
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
 
 
# Asset type names used in the CRISP template -> AssetTypeID in the database
TYPE_IDS = {
    "firewall": 1,
    "vpn endpoint": 2,
    "switch": 3,
    "access point": 4,
    "saas": 5,
}


def getColumn(df, targetRow, *names):
    # Find a column by its header name (not case-sensitive) and return that cell
    for column in df.columns:
        if str(column).strip().lower() in names:
            return df.at[targetRow, column]
    return None


def getData(df, targetRow, product):
    headers = [str(column).strip().lower() for column in df.columns]
    rowNumber = targetRow + 2  # +1 for the header row, +1 because rows start at 1

    # CRISP inventory template: Asset Name, Asset Type, Vendor, Product/Model, Version, Public Facing
    if "asset name" in headers:
        deviceName = getColumn(df, targetRow, "asset name")
        if isBlank(deviceName):
            return None

        typeName = getColumn(df, targetRow, "asset type")
        typeId = TYPE_IDS.get(str(typeName).strip().lower())
        if typeId is None:
            sys.exit(f'Row {rowNumber}: unknown asset type "{typeName}". '
                     'Use Firewall, VPN Endpoint, Switch, Access Point or SaaS.')

        vendor = getColumn(df, targetRow, "vendor")
        product = getColumn(df, targetRow, "product/model", "product")
        version = getColumn(df, targetRow, "version")
        publicFacing = str(getColumn(df, targetRow, "public facing")).strip().lower() in ("yes", "true")

    # Software installation exports: Device Name, Version, User (Name), ...
    else:
        deviceName = df.iloc[targetRow, 0]
        # AssetName is NOT NULL in the database, so a row with no name can't be inserted.
        if isBlank(deviceName):
            return None

        typeId = 5
        vendor = getColumn(df, targetRow, "vendor", "publisher")
        version = getColumn(df, targetRow, "version") if "version" in headers else df.iloc[targetRow, 1]
        publicFacing = False

    return (
        "INSERT INTO InventoryAsset "
        "(OrganizationID, AssetTypeID, AssetName, Vendor, Product, Version, Build, Hostname, PublicFacing, Status) "
        f"VALUES (1, {typeId}, {sqlValue(deviceName)}, {sqlValue(vendor)}, {sqlValue(product)}, {sqlValue(version)}, "
        f"NULL, NULL, {'TRUE' if publicFacing else 'FALSE'}, 'Active');"
    )
 
 
def main():
    parser = argparse.ArgumentParser(description="Clean CRISP inventory CSV files.")
    parser.add_argument("--input", type=Path, help="one uploaded CSV file")
    parser.add_argument("--output", type=Path, help="generated inventory SQL file")
    args = parser.parse_args()

    csvFiles = [args.input] if args.input else listFiles(inputPath)
    for csvFile in csvFiles:
        file = getFileName(csvFile)
        print(file)
        outputFile = args.output if args.output else outputPath / (file + "_inventory.sql")
        outputFile.parent.mkdir(parents=True, exist_ok=True)
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


if __name__ == "__main__":
    main()
