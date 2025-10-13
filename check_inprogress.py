import psycopg2
import psycopg2.extras

conn = psycopg2.connect(
    host='localhost',
    port=5432,
    database='lnsfirewall',
    user='postgres',
    password='lnsFirewall2024!'
)
cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

cur.execute("""
    SELECT id, status, response_data 
    FROM commands 
    WHERE status='in_progress' 
    ORDER BY created_at DESC 
    LIMIT 1
""")
row = cur.fetchone()

if row:
    print(f"In-progress command found:")
    print(f"  ID: {row['id']}")
    print(f"  Status: {row['status']}")
    print(f"  Response data: {row['response_data']}")
else:
    print("No in-progress commands found")

cur.close()
conn.close()

