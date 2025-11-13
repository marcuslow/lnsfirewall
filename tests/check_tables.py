import sqlite3
conn = sqlite3.connect('hq_database.db')
cur = conn.cursor()
cur.execute('SELECT name FROM sqlite_master WHERE type="table"')
tables = cur.fetchall()
print('Tables in database:')
for t in tables:
    print(f'  {t[0]}')
    # Show schema
    cur.execute(f'PRAGMA table_info({t[0]})')
    cols = cur.fetchall()
    print(f'    Columns: {", ".join([c[1] for c in cols])}')
conn.close()

