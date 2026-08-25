import socket
import struct


def start_server():
    HOST = "0.0.0.0"
    ICMP_CODE = socket.getprotobyname("icmp")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)

    known_clients = set()

    try:
        server_socket.bind((HOST, 0))

        print(f"🚀 [SERVER] started\n"
              f"⏳  Waiting for hidden nodes...\n"
              f"📍 Server is blind: all the date as well as the traffic is secured\n")

        while True:
            packet, addr = server_socket.recvfrom(2048)
            client_ip = addr[0]

            offset = 20 if len(packet) >= 28 else 0

            icmp_header = packet[offset:offset+8]

            if len(icmp_header) < 8:
                continue

            icmp_type, code, checksum, packet_id, sequence = struct.unpack('bbHHh', icmp_header)

            if icmp_type == 8:
                payload = packet[offset+8:]

                if client_ip not in known_clients:
                    known_clients.add(client_ip)
                    print(f"➕ [SERVER] Detected new anonymous node: {client_ip}")

                for other_ip in known_clients:
                    if other_ip != client_ip:
                        try:
                            reply_header = struct.pack('ddHHh', 0, 0, 0, packet_id, sequence)
                            server_socket.sendto(reply_header + payload, (other_ip, 0))
                        except Exception:
                            pass

    except KeyboardInterrupt:
        print("\r\nServer shutting down\r\n")
    except Exception as e:
        print(f"❌ [SERVER] Error: {e}")

    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()