import sqlite3
import uuid
import datetime

UIDSIZE = 16

def crate_new_uuid():
    return uuid.uuid4().bytes_le[:UIDSIZE]



def find_user(id, username):
    conn = sqlite3.connect('server.db')
    c = conn.cursor()
    c.execute("SELECT * FROM clients WHERE ID=? AND Name=?", (id, username))
    result = c.fetchone()
    if result is not None:
        boolresult = True
    else:
        boolresult = False
    conn.close()
    return boolresult




def file_verified(id, file_name):
    query = "UPDATE files SET Verified = ? WHERE ID = ? AND FileName = ?"
    data = (1, id, file_name)
    update_table(query, data)


def register_file_to_db(id, file_name, path):
    conn = sqlite3.connect('server.db')
    c = conn.cursor()
    c.execute("INSERT INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)", (id, file_name, path, 0))
    conn.commit()
    conn.close()



def get_rsakey(id_value):
    # Connect to the database
    conn = sqlite3.connect('server.db')
    cursor = conn.cursor()
    query = 'SELECT PublicKey FROM clients WHERE ID = ?'
    # Execute the query and fetch the result
    cursor.execute(query, (id_value,))
    result = cursor.fetchone()
    conn.close()
    # Return the AESKey if a result was found, or None if not
    if result is not None:
        return result[0]
    else:
        return None


def get_aeskey(id_value):
    # Connect to the database
    conn = sqlite3.connect('server.db')
    cursor = conn.cursor()
    query = 'SELECT AESKey FROM clients WHERE ID = ?'
    # Execute the query and fetch the result
    cursor.execute(query, (id_value,))
    result = cursor.fetchone()
    conn.close()
    # Return the AESKey if a result was found, or None if not
    if result is not None:
        return result[0]
    else:
        return None


def get_name(id_value):
    # Connect to the database
    conn = sqlite3.connect('server.db')
    cursor = conn.cursor()
    query = 'SELECT Name FROM clients WHERE ID = ?'
    # Execute the query and fetch the result
    cursor.execute(query, (id_value,))
    result = cursor.fetchone()
    conn.close()
    # Return the name if a result was found, or None if not
    if result is not None:
        return result[0]
    else:
        return None


def update_table(query, data):
    # Establish connection to database and Create cursor object
    conn = sqlite3.connect('server.db')
    cursor = conn.cursor()
    cursor.execute(query, data)
    conn.commit()
    cursor.close()
    conn.close()


def update_date(id):
    query = "UPDATE clients SET LastSeen = ? WHERE ID = ?"
    data = (datetime.datetime.now(), id)
    update_table(query, data)


def update_keys(rsakey, aeskey, id):
    query = "UPDATE clients SET PublicKey = ?, AESKey = ? WHERE ID = ?"
    data = (rsakey, aeskey, id)
    update_table(query, data)






def create_users_table():
    # Connect to the database
    conn = sqlite3.connect('server.db')

    # Construct the SQL query for creating the table
    query = 'CREATE TABLE IF NOT EXISTS clients ('
    query += 'ID binary(128) PRIMARY KEY, '
    query += 'Name TEXT(255), '
    query += 'PublicKey binary(1280), '
    query += 'LastSeen DATETIME,'
    query += 'AESKey binary(128))'
    
    # Create the users table if it doesn't exist
    cursor = conn.cursor()
    cursor.execute(query)

    # Commit the changes and close the database connection
    conn.commit()
    conn.close()




def create_files_table():
    # Connect to the database
    conn = sqlite3.connect('server.db')

    # Construct the SQL query for creating the table
    query = 'CREATE TABLE IF NOT EXISTS files ('
    query += 'ID binary(128), '
    query += 'FileName TEXT(255), '
    query += 'PathName TEXT(255), '
    query += 'Verified BOOLEAN)'
    
    # Create the users table if it doesn't exist
    cursor = conn.cursor()
    cursor.execute(query)

    # Commit the changes and close the database connection
    conn.commit()
    conn.close()




def check_username(username):
    conn = sqlite3.connect('server.db')
    c = conn.cursor()

    # Query the database for the given username
    c.execute("SELECT COUNT(*) FROM clients WHERE Name=?", (username,))
    result = c.fetchone()[0]

    # If the count is greater than 0, the username exists
    if result > 0:
        return 0
    else:
    # Add the new username to the database
        uid = crate_new_uuid() 
        c.execute("INSERT INTO clients (ID,Name) VALUES (?,?)", (uid,username,))
        conn.commit()
        conn.close()
        update_date(uid)
        return uid


