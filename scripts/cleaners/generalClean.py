import pandas as pd
from pathlib import Path
import json

inputPath = Path.home() / "Projects" / "softwareClass" / "inputs"
outputPath = Path.home() / "Projects" / "softwareClass" / "tmp"

def listFiles(inputPath):
    csvFiles = list(inputPath.glob("*csv"))
    return csvFiles

def getFileName(filePath):
    pathWithoutExt = filePath.with_suffix("")
    file = str(pathWithoutExt)
    split = file.split("/")
    
    return split[6]


def getProductName(inputFileName):
    
    split01 = inputFileName.split("installation")
    split02 = split01[0].split("_")

    productName = " ".join(split02).strip()
    return productName



def getData(inputFile, targetRow, product, jsonData):
    df = pd.read_csv(inputFile)

    deviceName = df.iloc[targetRow, 0]
    Version = df.iloc[targetRow, 1]

    data = {
            "deviceName": deviceName,
            "product": product,
            "version": Version,
            "filename": str(inputFile)
        }

    jsonData.append(data)

def writeJson(inputFile, deviceName, Version, product, data):
    data = {
        "deviceName": deviceName,
        "product": product,
        "version": Version,
        "filename": str(inputFile)
    }

    with open(outputFile, "w") as file:
        json.dump(data, file, indent=4)

csvFiles = listFiles(inputPath)
for i in range(len(csvFiles)):
    jsonData = []
    file = getFileName(csvFiles[i])
    print (file)
    outputFile = outputPath / (file + ".json")
    df = pd.read_csv(csvFiles[i])
    rowCount = len(df.index)
    productName = getProductName(file) #this needs work

    for row in range(0, rowCount):
        getData(csvFiles[i], row, productName, jsonData) #needs work
        print ("row #", row)
    
    with open(outputFile, "w") as file:
        json.dump(jsonData, file, indent=4)
    print("done, output file = ", outputFile)




    