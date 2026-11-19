from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent

scripts = [
    #(ROOT / "cleaners" / "firewallClean.py", []),
    #(ROOT / "cleaners" / "generalClean.py", []),
    #(ROOT / "cleaners" / "loadInventory.py", ["--docker"]),
    #(ROOT / "agents" / "research" / "researchAgent.py", []),
    #(ROOT / "agents" / "reports" / "correlationCOPY.py", []),
    (ROOT / "agents" / "analyzerAgent.py", []),
    #ROOT / "agents" / "qaAgent.py",
]

for script, arguments in scripts:

    print(f"\nRunning: {script.name}")
    print("-" * 50)

    result = subprocess.run(
        [sys.executable, str(script), *arguments]
    )

    if result.returncode != 0:
        print(f"\nERROR: {script.name} failed.")
        sys.exit(result.returncode)

    print(f"{script.name} completed successfully.")
    time.sleep(5)

print("\nCRISP processing complete.")