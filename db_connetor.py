import sqlite3

def init_db(db_name="z_net_satut.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS snmp_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip TEXT,
            oid TEXT,
            value TEXT,
            status TEXT
        )
    ''')
    conn.commit()
    return conn

def save_to_db(conn, results):
    cursor = conn.cursor()
    for res in results:
        cursor.execute('''
            INSERT INTO snmp_metrics (ip, oid, value, status)
            VALUES (?, ?, ?, ?)
        ''', (res['ip'], res['oid'], str(res['value']), res['status']))
    conn.commit()