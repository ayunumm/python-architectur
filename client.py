import socket
def connect_to_server(host, port):
    # Create a socket object using IPv4 and TCP protocol
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client_socket.connect((host, port))

    # Receive data from the server
    data = client_socket.recv(1024)  # Buffer size of 1024 bytes
    print("Received from server:", data.decode())  # Decode bytes to string

    # Close the socket
    client_socket.close()

# Connect to the server with local host IP and port 12345
connect_to_server('192.168.2.11', 12345)
