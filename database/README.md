CRISP Database
Requirements
Docker Desktop
DBeaver (Recommended)
Start Database
Open a terminal in the database folder and run:

docker compose up -d
Connect to PostgreSQL
Host: localhost

Port: 5432

Database: crisp

Username: postgres

Password: crisppassword

Verify Setup
Run:

SELECT * FROM Organization;
Expected result:

SpawGlass
Rebuild Database
WARNING: This deletes all data.

docker compose down -v
docker compose up -d