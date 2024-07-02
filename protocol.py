import os
import keyhandler
import struct
import sqlhandler

SERVERVERSION = b'3'
UIDMSG = 's H I 16s '

CODEREGISTER = 1100
CODERSASENDING = 1101
CODECONNECT = 1102
CODEFILESENDING = 1103
CODECRCOK = 1104
CODECRCERROR1 = 1105
CODECRCERROR2 = 1106

CODEREGISTEROK = 2100
CODEREGISTERFAILED = 2101
CODERSASUCCESS = 2102
CODECRCSUCCESS = 2103
CODEFINISH = 2104
CODELOGINCONFIRM = 2105
CODELOGINREGECT = 2106

USERNAMESIZE = 255
RSAKEYSIZE = 160
FILEBYTES = 742
FILESTARTBYTES = 282




def handle_client(client_socket):
    keep_communication = True
    while keep_communication:    
         
        msg = failed()
        try:
            received_data = client_socket.recv(1024)
            client_input = protocol_handler(received_data)
            
            
            #   if the user sending file
            if client_input['code'] == CODEFILESENDING:     #1103
                msg = new_file_handler(client_input, client_socket, received_data)
                
            # register if the user name do not exist in database
            elif client_input['code'] == CODEREGISTER: 
                user_check = register_user(client_input)
                keep_communication = user_check[0]
                msg = user_check[1]   
            # generate new aes key by given rsa                     
            elif client_input['code'] == CODERSASENDING:              
                msg = send_aes_key_first_time(client_input)
                
            elif  client_input['code'] == CODECRCOK or client_input['code'] == CODECRCERROR2: 
                msg = finish(client_input)
                keep_communication = False 
            # login again
            elif client_input['code'] == CODECONNECT:            
                user_check = login(client_input) 
                msg =  user_check[1]
                keep_communication = user_check[0]
            # waiting for new file input
            elif client_input['code'] == CODECRCERROR1:        
                msg = struct.pack(UIDMSG, SERVERVERSION, CODEFINISH , sqlhandler.UIDSIZE, client_input['client_id'])
            #code do not exist or there other problem
            else:  
                msg = failed()
                keep_communication = False    
                
            # send the mssage to the client   
            client_socket.sendall(msg)
            
        # if there any exception
        except Exception as e:
            keep_communication = False
            msg = failed()
            client_socket.sendall(msg)

    client_socket.close()        
    


#save the data from bytes to dec
def protocol_handler(received_data):
    data_dic = {}
    data_dic["client_id"] = (received_data[0:16])
    data_dic["client_version"] = int.from_bytes(received_data[16:17], "little")     
    request_code = (received_data[18:20])
    data_dic["code"] =  (struct.unpack('H'*(len(request_code)//2),request_code))[0]
    data_dic["payload_size"]= int.from_bytes(received_data[20:24], "little")      
    if data_dic["code"] == 1103:
        data_dic["payload"] = received_data[24:1024]
    else:
        data_dic["payload"] = received_data[24:24+data_dic['payload_size']]     
    return data_dic
        
    


def register_user(client_input):
    user_name = ascii_decode(client_input['payload'])
    # crate new uid if the user do not exist in table
    uid = sqlhandler.check_username(user_name) 
    if uid != 0:
        return [True, struct.pack(UIDMSG, SERVERVERSION, CODEREGISTEROK, sqlhandler.UIDSIZE, uid)]
    return [False, struct.pack(UIDMSG, SERVERVERSION, CODEREGISTERFAILED, sqlhandler.UIDSIZE, bytes("register failed!",'utf-8'))]





def send_aes_key_first_time(client_input):  
    client_id = client_input['client_id']
    rsa_key = client_input['payload'][USERNAMESIZE:USERNAMESIZE + RSAKEYSIZE]
    
    # updata the rsa and aes key in table
    aes_key = keyhandler.generate_aes_cbc_key(rsa_key)
    encrypted_aes_key = aes_key[1]
    sqlhandler.update_keys(rsa_key, aes_key[0], client_id)
    aes_msg = UIDMSG + str(len(encrypted_aes_key)) + 's' 
    return struct.pack(aes_msg, SERVERVERSION, CODERSASUCCESS, len(client_id)+ len(encrypted_aes_key), client_id, encrypted_aes_key)


  
  

def get_data(client_socket, expected_size):
    # receive chuks of data from the client - when client send files
    data = b''
    total_received = 0
    
    while total_received < expected_size:
        chunk = client_socket.recv(expected_size - total_received)
        if not chunk:
            break
        data += chunk
        total_received += len(chunk)
    return data



def new_file_handler(client_input, client_socket, received_data):   
    file_size = int.from_bytes(client_input['payload'][0:4], "little") 
    fn =  client_input['payload'][4:4+254]
    filename = ascii_decode(client_input['payload'][4:4+254].replace(b'\x00', b''))
    
    if (file_size - FILEBYTES) > 0:     # FILEBYTES = 742 = 1024 - the protocol data that not the file 
        received_data  += get_data(client_socket, file_size - FILEBYTES) 
        
    data = received_data[FILESTARTBYTES :]      # FILESTARTBYTES = 282 = 1024 - FILEBYTES(742)
    
    aes = sqlhandler.get_aeskey(client_input['client_id'])
    data = keyhandler.decrypt_with_cbc(data, aes) 
    name = sqlhandler.get_name(client_input['client_id'])[:25]      #take the first 25 chars  of user name
    
    save_bytes_to_file(data, filename, name)
    location = "clientfiles/" + name+ "/" + filename
    sqlhandler.register_file_to_db(client_input['client_id'], filename, location)
    crc = keyhandler.crc32_file(location)
    return struct.pack(UIDMSG +'I 255s I', SERVERVERSION, CODECRCSUCCESS, sqlhandler.UIDSIZE, client_input['client_id'], file_size, fn, crc)         



def save_bytes_to_file(data_bytes, filename, username):
    # Get the absolute path of the current script file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Create the folder if it doesn't already exist
    folder_path = os.path.join(current_dir, "clientfiles", username)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    # Create the file
    file_path = os.path.join(folder_path, filename)
    # Write the bytes to the output file
    with open(file_path, 'wb') as f:
        f.write(data_bytes)


#code 1104 or 1106
def finish(client_input):
    if client_input['code'] == CODECRCOK:       # 1104
        filename = ascii_decode(client_input['payload'][0:254].replace(b'\x00', b''))
        sqlhandler.file_verified(client_input['client_id'], filename)
        
    return struct.pack(UIDMSG, SERVERVERSION, CODEFINISH , sqlhandler.UIDSIZE, client_input['client_id'])
  
#code 1102
def login(client_input):
    id = client_input['client_id']
    name = ascii_decode(client_input['payload'][0:255])
    userisexist = sqlhandler.find_user(id, name)
    if userisexist:
         # updata the aes key in table
        rsa_key = sqlhandler.get_rsakey(id)     
        aes_key = keyhandler.generate_aes_cbc_key(rsa_key)
        encrypted_aes_key = aes_key[1]
        sqlhandler.update_keys(rsa_key, aes_key[0], id)    
        
        aes_msg = UIDMSG + str(len(encrypted_aes_key)) + 's' 
        return [True, struct.pack(aes_msg, SERVERVERSION, CODELOGINCONFIRM, len(id)+ len(encrypted_aes_key), id, encrypted_aes_key)]
    else:
        return [False, struct.pack(UIDMSG, SERVERVERSION, CODELOGINREGECT, len(id), id)]


def failed():  
    return struct.pack('s H I',SERVERVERSION, 2107, 0)

def ascii_decode(input):
    return input.decode("ascii")
