
import socket
import threading
import sqlhandler
import protocol
import sqlhandler



def get_port():
    try:
        with open('port.info', 'r') as f:
            port = f.read().strip()
    except FileNotFoundError:
        print("Warning: 'port.info' file not found, using default port number")
        port = '1234'
    except Exception as e:
        print(f"Error reading port.info file: {e}")
        port = '1234'
    return int(port)



def start_server():
    
    sqlhandler.create_users_table() 
    sqlhandler.create_files_table()
    host = '127.0.0.1'
    port = get_port()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    print(f'Server listening on {host}:{port}')
    while True:
        conn, addr = server_socket.accept()
        print(f'Connected by {addr}')
        threading.Thread(target=protocol.handle_client, args=(conn, )).start()





if __name__ == '__main__':
    start_server()