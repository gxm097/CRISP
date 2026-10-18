import pandas as pd
from pathlib import Path

softwareList = Path.home() / "Projects" / "softwareClass" / "inputs" / "software_export_289522_16000069920.csv"


def findProductIndex(softwareList, ProductName):
    df = pd.read_csv(softwareList)

    for i in range(len(df)):
        if df.iloc[i, 0] == ProductName:
            rawRow = df.iloc[i]
            exit
        print("could not find the product in the list")

    return i, rawRow


ProductName = "GoToAssist Customer 4.8.0.1702"
index, rawInfo = findProductIndex(softwareList, ProductName)
print("index: ", index, " ++ ", rawInfo)