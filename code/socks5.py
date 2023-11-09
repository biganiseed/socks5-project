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
        self.client_count = 0
        print(f"Listening on {host}:{port}")

    def get_methods(self, nmethods, client):
        methods = []
        if nmethods > 0:
            methods_data = client.recv(nmethods)
            methods = list(methods_data)
        return methods

    # Socks5 client and server handshake.
    # Return remote socket which the client wants to connect.
    def handshake(self, client):
        buff = None
        try:
            # First, negotiate authetication method
            # 1st Request structure:
            # +----+----------+----------+
            # |VER | NMETHODS | METHODS  |
            # +----+----------+----------+
            # | 1  |    1     | 1 to 255 |
            # +----+----------+----------+
            # version, nmethods, methods = struct.unpack('!BBB', client.recv(3))
            version, nmethods = struct.unpack('!BB', client.recv(2))
            methods = self.get_methods(nmethods, client)
            # Reply there is no authentication required
            client.sendall(struct.pack('!BB', 0x05, 0x00))  

            # Then, client tells remote address and port
            # 2nd Request structure:
            # +----+-----+-------+------+----------+----------+
            # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            # +----+-----+-------+------+----------+----------+
            # | 1  |  1  | X'00' |  1   | Variable |    2     |
            # +----+-----+-------+------+----------+----------+
            buff = client.recv(4)
            version, cmd, _, address_type = struct.unpack('!BBBB', buff)
            if address_type == 1:  # IPv4
                buff = client.recv(4)
                remote_address = socket.inet_ntoa(buff)
            elif address_type == 3:  # Domain name
                buff = client.recv(1)
                domain_length = buff[0]
                buff = client.recv(domain_length)
                remote_address = buff
            elif address_type == 4:  # IPv6
                print("IPv6 is unsupported yet.")
                return None
            else:
                print("Unsupported address_type:", address_type)
                return None
            buff = client.recv(2)
            remote_port = struct.unpack('!H', buff)[0]

            # Connect to remote
            if remote_address and remote_port:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((remote_address, remote_port))
                bind_address = remote.getsockname()
                print(f"Connected to {remote_address}:{remote_port}")

            # Reply success to client
            # Reply structure:
            # +----+-----+-------+------+----------+----------+
            # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            # +----+-----+-------+------+----------+----------+
            # | 1  |  1  | X'00' |  1   | Variable |    2     |
            # +----+-----+-------+------+----------+----------+
            # Convert IP address to an integer
            packed_ip = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            reply = struct.pack('!BBBBIH', 0x05, 0x00, 0x00, 1, packed_ip, bind_address[1])
            client.sendall(reply)

            return remote
        except Exception as e:
            print("Error with client:", client.getpeername(), "last request:", buff)
            print(e.args)
            if 'remote_address' in locals() and 'remote_port' in locals():
                print("Remote address:", remote_port, "remote_port:", port)
            return None

    def proxy_client(self, client):
        remote = self.handshake(client)
        if remote:
            self.relay_data(client, remote)
            remote.close()
        client.close()

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

    def run(self):
        socket.setdefaulttimeout(5)
        print("Starting SOCKS5 server")
        while True:
            client, address = self.server.accept()
            self.client_count += 1
            print(f"Accepted connection {self.client_count} from {address[0]}:{address[1]}")
            proxy = threading.Thread(target=self.proxy_client, args=(client,))
            proxy.start()

if __name__ == '__main__':
    proxy = SocksProxy()
    proxy.run()
