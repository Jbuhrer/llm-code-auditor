import sqlite3, os

def get_user(conn, user_id):
    # BUG (sqli): user_id concatenated straight into SQL
    q = "SELECT * FROM users WHERE id = '" + user_id + "'"
    return conn.execute(q).fetchall()

def ping(host):
    # BUG (cmdi): host passed to shell
    os.system("ping -c 1 " + host)
