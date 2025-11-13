import psycopg2

conn = psycopg2.connect(
    host='localhost',
    port=5432,
    database='lnsfirewall',
    user='postgres',
    password='lnsFirewall2024!'
)
cur = conn.cursor()

print("Current clients in database:")
cur.execute("SELECT id, client_name FROM clients")
rows = cur.fetchall()
for r in rows:
    print(f"  id={r[0]}, name={r[1]}")

print("\nSample commands:")
cur.execute("SELECT id, client_id, command_type FROM commands LIMIT 5")
rows = cur.fetchall()
for r in rows:
    print(f"  command_id={r[0][:20]}..., client_id={r[1]}, type={r[2]}")

cur.close()
conn.close()

