import sqlite3

# to start database: sqlite3 database.db < schema.sql
def connect_to_db(database):
    db = sqlite3.connect(database)
    db.row_factory = sqlite3.Row
    return db

def query_db(db, query, args=()):
    cur = db.execute(query, args)
    ret = cur.fetchall()
    return ret if ret else None
