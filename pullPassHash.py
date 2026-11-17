import psycopg
from psycopg.rows import dict_row

DSN = "postgresql://postgres:crisppassword@localhost:5432/crisp"

def getPassHash(userName, organizationID):
    with psycopg.connect(DSN) as connection:
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                "SELECT password_hash FROM user_account "
                "WHERE organization_id = %s AND username = %s",
                (organizationID, userName),
            )
            row = cursor.fetchone()
            storedHash = row["password_hash"] if row else None
    return storedHash