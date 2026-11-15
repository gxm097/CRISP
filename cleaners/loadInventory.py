
#!/usr/bin/env python3
"""
Load the SQL files written by Firewallclean.py / generalclean.py (tmp/*_inventory.sql)
into the PostgreSQL database that was created with init.sql.
 
Put this file next to the cleaner scripts (scripts/loadinventory.py), then run:
 
    python scripts/loadinventory.py --docker --dry-run   # runs everything, then rolls back
    python scripts/loadinventory.py --docker             # loads for real
 
--docker runs psql INSIDE the CRISP docker compose container, so nothing needs to be
installed on your machine except Docker. Defaults match docker-compose.yml:
container crisp_postgres, user postgres, database crisp (override with
--container / --pg-user / --pg-db).
 
Without --docker the script uses a psql installed on this machine. Choose the database with
  --db "postgresql://user:password@host:5432/dbname"
  or the DATABASE_URL environment variable
  or the standard PGDATABASE (+ PGHOST / PGUSER / PGPASSWORD) variables.
The script never guesses a database; if none is given it stops.
 
Safety behaviour:
  * Checks the database really was built from init.sql (Organization 1 exists and the
    AssetType IDs 1/3/4/5 are Firewall/Switch/Access Point/SaaS, which the cleaners hard-code).
  * Only runs files made up entirely of single-line "INSERT INTO InventoryAsset ..." statements.
  * Each file is loaded in its own transaction and rolled back unless the number of rows
    inserted equals the number of statements in the file.
  * Records each file in InventoryImport and tags its assets with that ImportID, and refuses
    to load a file name that was already imported (use --force to override).
 
Python standard library only. Exit codes: 0 = success, 1 = a load or check failed,
2 = bad usage / missing tool / no database given.
"""
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
 
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIR = ROOT / "tmp"
 
ORG_ID = 1  # the cleaner scripts hard-code OrganizationID 1 (SpawGlass in init.sql)
ASSET_TYPES = "(1,'Firewall'),(3,'Switch'),(4,'Access Point'),(5,'SaaS')"
INSERT_PREFIX = "INSERT INTO InventoryAsset "
 
# Defaults taken from docker-compose.yml
DOCKER_CONTAINER = "crisp_postgres"
DOCKER_USER = "postgres"
DOCKER_DB = "crisp"
 
PREFLIGHT_SQL = f"""
SELECT 'database|' || current_database() || ' as ' || current_user;
SELECT 'org|' || COUNT(*) FROM Organization WHERE OrganizationID = :org;
SELECT 'types|' || COUNT(*) FROM AssetType WHERE (AssetTypeID, AssetTypeName) IN ({ASSET_TYPES});
SELECT 'assets|' || COUNT(*) FROM InventoryAsset;
"""
 
PREFLIGHT_TRACKING_SQL = """
SELECT 'imports|' || COUNT(*) FROM InventoryImport;
SELECT 'user|' || COUNT(*) FROM user_account WHERE user_id = :user_id;
"""
 
ALREADY_LOADED_SQL = """
SELECT 'count|' || COUNT(*) FROM InventoryImport WHERE OrganizationID = :org AND Filename = :'fname';
"""
 
 
def die(message, code=1):
    print("ERROR: " + message, file=sys.stderr)
    sys.exit(code)
 
 
def runCommand(cmd, stdinText=None, timeout=300):
    # Bytes in, bytes out: avoids Windows code-page and CRLF translation of the SQL.
    try:
        done = subprocess.run(
            cmd,
            input=None if stdinText is None else stdinText.encode("utf-8"),
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        die(f"'{cmd[0]}' did not finish within {timeout} seconds")
    except OSError as error:
        die(f"could not run '{cmd[0]}': {error}", 2)
    return SimpleNamespace(
        returncode=done.returncode,
        stdout=done.stdout.decode("utf-8", "replace"),
        stderr=done.stderr.decode("utf-8", "replace"),
    )
 
 
def checkDocker(container):
    if shutil.which("docker") is None:
        die("the docker command-line client is not on PATH (is Docker Desktop installed and running?).", 2)
    result = runCommand(["docker", "inspect", "-f", "{{.State.Running}}", container], timeout=60)
    if result.returncode != 0:
        die(f"could not inspect Docker container '{container}'. Is Docker Desktop running, and has the "
            "database been started with 'docker compose up -d'?\n"
            "docker said: " + result.stderr.strip())
    if result.stdout.strip() != "true":
        die(f"Docker container '{container}' exists but is not running. Start it with 'docker compose up -d'.")
 
 
def resolveTarget(args):
    if args.docker or args.container:
        if args.db:
            die("use either --db (psql on this machine) or --docker, not both.", 2)
        container = args.container or DOCKER_CONTAINER
        checkDocker(container)
        return {"kind": "docker", "container": container, "user": args.pg_user, "db": args.pg_db,
                "label": f"Docker container {container}"}
 
    url = args.db or os.environ.get("DATABASE_URL")
    if url:
        dbArg = [url]
    elif os.environ.get("PGDATABASE"):
        dbArg = []
    else:
        die("no database specified. Use --docker for the CRISP docker compose database, or pass --db, "
            "or set DATABASE_URL or PGDATABASE (plus PGHOST / PGUSER / PGPASSWORD as needed).", 2)
    if shutil.which("psql") is None:
        die("the psql client is not installed on this machine. If your database runs in Docker, "
            "use --docker instead (it runs psql inside the container).", 2)
    return {"kind": "host", "dbArg": dbArg, "label": "psql on this machine"}
 
 
def buildCommand(target, variables):
    psql = ["psql", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1"]
    for key, value in variables.items():
        psql += ["-v", f"{key}={value}"]
    if target["kind"] == "docker":
        return ["docker", "exec", "-i", target["container"]] + psql + ["-U", target["user"], "-d", target["db"]]
    return psql + target["dbArg"]
 
 
def runPsql(target, sql, variables):
    script = "SET client_encoding TO 'UTF8';\n" + sql
    return runCommand(buildCommand(target, variables), script)
 
 
def parseKeyValues(output):
    pairs = {}
    for line in output.splitlines():
        if "|" in line:
            key, value = line.split("|", 1)
            pairs[key.strip()] = value.strip()
    return pairs
 
 
def preflight(target, track, userId):
    sql = PREFLIGHT_SQL + (PREFLIGHT_TRACKING_SQL if track else "")
    result = runPsql(target, sql, {"org": ORG_ID, "user_id": userId})
    if result.returncode != 0:
        die("could not connect, or the schema check failed. If the database container only just "
            "started, wait a few seconds and retry; otherwise check that init.sql ran "
            "('docker compose logs postgres').\npsql said:\n" + result.stderr.strip())
    info = parseKeyValues(result.stdout)
 
    if info.get("org") != "1":
        die(f"Organization {ORG_ID} does not exist in this database; this is not an init.sql database.")
    if info.get("types") != "4":
        die("AssetType rows do not match init.sql (expected IDs 1=Firewall, 3=Switch, "
            "4=Access Point, 5=SaaS). The generated SQL hard-codes those IDs, so loading "
            "would assign the wrong asset types.")
    if track and info.get("user") != "1":
        die(f"user_account has no user_id {userId}, which InventoryImport.UploadedByUserID needs. "
            "Pass an existing id with --user-id, or use --no-track.")
    return info
 
 
def alreadyLoaded(target, fileName):
    result = runPsql(target, ALREADY_LOADED_SQL, {"org": ORG_ID, "fname": fileName})
    if result.returncode != 0:
        die("could not check InventoryImport for earlier loads:\n" + result.stderr.strip())
    return int(parseKeyValues(result.stdout).get("count", "0")) > 0
 
 
def readStatements(path):
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        die(f"{path.name} is not valid UTF-8, so it was not run.")
    lines = [line for line in text.splitlines() if line.strip()]
    for number, line in enumerate(lines, 1):
        if not (line.startswith(INSERT_PREFIX) and line.rstrip().endswith(";")):
            die(f"{path.name} line {number} is not a single-line InventoryAsset INSERT, "
                "so it was not run. (A CSV cell containing a line break can cause this.)")
    return lines
 
 
def buildScript(body, track, dryRun):
    lines = [
        "BEGIN;",
        r"SELECT COALESCE(MAX(AssetID), 0) AS before_max FROM InventoryAsset \gset",
    ]
    if track:
        lines.append(
            "INSERT INTO InventoryImport (OrganizationID, UploadedByUserID, Filename) "
            r"VALUES (:org, :user_id, :'fname') RETURNING ImportID AS import_id \gset"
        )
    lines.append(body)
    lines.append(r"SELECT COUNT(*) AS inserted FROM InventoryAsset WHERE AssetID > :before_max \gset")
    if track:
        lines.append("UPDATE InventoryAsset SET ImportID = :import_id "
                     "WHERE AssetID > :before_max AND ImportID IS NULL;")
    lines += [
        r"SELECT (:inserted = :expected) AS ok \gset",
        r"\if :ok",
        "ROLLBACK;" if dryRun else "COMMIT;",
        r"\else",
        "ROLLBACK;",
        r"\endif",
        r"\echo RESULT inserted=:inserted expected=:expected ok=:ok",
    ]
    return "\n".join(lines) + "\n"
 
 
def loadFile(target, path, lines, track, userId, dryRun):
    script = buildScript("\n".join(lines), track, dryRun)
    variables = {"org": ORG_ID, "user_id": userId, "fname": path.name, "expected": len(lines)}
    result = runPsql(target, script, variables)
    if result.returncode != 0:
        die(f"{path.name} failed and was rolled back. Nothing from this file was saved.\n"
            "psql said:\n" + result.stderr.strip())
 
    resultLine = next((l for l in result.stdout.splitlines() if l.startswith("RESULT ")), None)
    if resultLine is None:
        die(f"{path.name}: psql finished without a result line, so the outcome is unknown. "
            "Check the database before retrying.\n" + result.stdout + result.stderr)
    fields = dict(part.split("=", 1) for part in resultLine.split()[1:])
    if fields.get("ok") != "t":
        die(f"{path.name}: inserted {fields.get('inserted')} rows but expected {fields.get('expected')}. "
            "Rolled back; nothing was saved.")
    return int(fields["inserted"])
 
 
def main():
    parser = argparse.ArgumentParser(description="Load generated inventory SQL files into PostgreSQL.")
    parser.add_argument("files", nargs="*", type=Path,
                        help="SQL files to load (default: every *_inventory.sql in the tmp folder)")
    parser.add_argument("--docker", action="store_true",
                        help=f"run psql inside the docker compose container ({DOCKER_CONTAINER})")
    parser.add_argument("--container", help=f"docker container name (implies --docker; default {DOCKER_CONTAINER})")
    parser.add_argument("--pg-user", default=DOCKER_USER, help=f"database user in docker mode (default {DOCKER_USER})")
    parser.add_argument("--pg-db", default=DOCKER_DB, help=f"database name in docker mode (default {DOCKER_DB})")
    parser.add_argument("--db", help="connection URI for a psql on this machine, e.g. "
                                     "postgresql://user:pass@host:5432/dbname (default: DATABASE_URL or PG* variables)")
    parser.add_argument("--dry-run", action="store_true", help="do everything, then roll back")
    parser.add_argument("--force", action="store_true", help="load a file even if its name was already imported")
    parser.add_argument("--no-track", action="store_true",
                        help="do not record the load in InventoryImport (disables the duplicate-file check)")
    parser.add_argument("--user-id", type=int, default=1,
                        help="user_account.user_id recorded as the uploader (default 1)")
    args = parser.parse_args()
    track = not args.no_track
 
    target = resolveTarget(args)
 
    files = args.files or sorted(DEFAULT_DIR.glob("*_inventory.sql"))
    if not files:
        die(f"no *_inventory.sql files found in {DEFAULT_DIR}. Run the cleaner scripts first.")
    for path in files:
        if not path.is_file():
            die(f"file not found: {path}")
 
    info = preflight(target, track, args.user_id)
    print(f"Connected to {info.get('database')} via {target['label']}. Schema check passed "
          f"({info.get('assets')} existing assets).")
    if args.dry_run:
        print("DRY RUN: every file is loaded inside a transaction that is rolled back.")
 
    totalAssets = 0
    for number, path in enumerate(files, 1):
        lines = readStatements(path)
        label = f"[{number}/{len(files)}] {path.name}"
        if not lines:
            print(f"{label}: SKIPPED (file is empty)")
            continue
        if track and not args.force and alreadyLoaded(target, path.name):
            print(f"{label}: SKIPPED (a file with this name is already in InventoryImport; use --force to load anyway)")
            continue
        inserted = loadFile(target, path, lines, track, args.user_id, args.dry_run)
        totalAssets += inserted
        outcome = "OK, rolled back (dry run)" if args.dry_run else "LOADED"
        print(f"{label}: {outcome}, {inserted} assets")
 
    verb = "would load" if args.dry_run else "loaded"
    print(f"DONE: {verb} {totalAssets} assets from {len(files)} file(s).")
 
 
if __name__ == "__main__":
    main()
 