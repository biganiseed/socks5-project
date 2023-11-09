import socket
import threading
import struct
import select

class SocksProxy:
    def __init__(self, host='0.0.0.0', port=10800):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Enable port reuse when the port is not released by last process yet.
        self.server.bind((host, port))
        self.server.listen(5)
        self.clientCount = 0
        print(f"Listening on {host}:{port}")


    def handle_client(self, client_socket):
        try:
            # Greeting header
            # +----+----------+----------+
            # |VER | NMETHODS | METHODS  |
            # +----+----------+----------+
            # | 1  |    1     | 1 to 255 |
            # +----+----------+----------+
            version, nmethods, methods = struct.unpack('!BBB', client_socket.recv(3))
            client_socket.sendall(struct.pack('!BB', 0x05, 0x00))  # No authentication required

            # Request header
            # +----+-----+-------+------+----------+----------+
            # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            # +----+-----+-------+------+----------+----------+
            # | 1  |  1  | X'00' |  1   | Variable |    2     |
            # +----+-----+-------+------+----------+----------+
            version, cmd, _, address_type = struct.unpack('!BBBB', client_socket.recv(4))
            if address_type == 1:  # IPv4
                address = socket.inet_ntoa(client_socket.recv(4))
            elif address_type == 3:  # Domain name
                domain_length = client_socket.recv(1)[0]
                address = client_socket.recv(domain_length)
            else:
                print("Unsupported address_type:", address_type)
                return
            port = struct.unpack('!H', client_socket.recv(2))[0]


            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((address, port))
            bind_address = remote.getsockname()
            print(f"Connected to {address}:{port}")

            # Reply header
            # +----+-----+-------+------+----------+----------+
            # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            # +----+-----+-------+------+----------+----------+
            # | 1  |  1  | X'00' |  1   | Variable |    2     |
            # +----+-----+-------+------+----------+----------+
            # Convert IP address to an integer
            packed_ip = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            reply = struct.pack('!BBBBIH', 0x05, 0x00, 0x00, 1, packed_ip, bind_address[1])
            client_socket.sendall(reply)

            # Relay data
            self.relay_data(client_socket, remote)
        except Exception as e:
            print("Error with client_socket:", client_socket.getpeername())
            print(e.args)
            if 'address' in locals() and 'port' in locals():
                print("Remote address:", address, "port:", port)
        finally:
            if 'remote' in locals():
                remote.close()
            client_socket.close()

    def relay_data(self, client, remote):
        try:
            while True:
                r, w, e = select.select([client, remote], [], [])
                if client in r:
                    data = client.recv(4096)
                    if len(data) <= 0:  # No data received, connection closed
                        break
                    remote.sendall(data)
                if remote in r:
                    data = remote.recv(4096)
                    if len(data) <= 0:  # No data received, connection closed
                        break
                    client.sendall(data)
        except Exception as e:
            print("Error when relaying data.")
            print(e.args)
            remote.close()
            client.close()


    def run(self):
        socket.setdefaulttimeout(5)
        print("Starting SOCKS5 server")
        while True:
            client_sock, address = self.server.accept()
            self.clientCount += 1
            print(f"Accepted connection {self.clientCount} from {address[0]}:{address[1]}")
            client_handler = threading.Thread(target=self.handle_client, args=(client_sock,))
            client_handler.start()

if __name__ == '__main__':
    proxy = SocksProxy()
    proxy.run()
