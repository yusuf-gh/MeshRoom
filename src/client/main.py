import socket, struct, threading, sys, hashlib, base64
from cryptography.fernet import Fernet
from src.utils import calculate_checksum


def listen_servers_pongs(client_socket, cipher, server_ip):
    while True:
        try:
            packet, addr = client_socket.recvfrom(2048)


            if addr[0] == server_ip:

                offset = 20 if len(packet) >= 28 else 0

                icmp_header = packet[offset:offset+8]

                if len(icmp_header) < 8:
                    continue

                icmp_type, code, checksum, packet_id, sequence = struct.unpack('ddHHh', icmp_header)

                if icmp_type == 0:
                    payload = packet[offset+8:]

                    if payload:
                        try:

                            decrypted_message = cipher.decrypt(payload).decode('utf-8')
                            print(f"\n{decrypted_message}")

                        except Exception:
                            pass
        except Exception:
            break


def start_client():
    print("🔒 [MeshRoom Client] Initialization...")

    room_password = input("🔑 Enter Room Password (must be identical for all peers): ").encode()
    key = base64.urlsafe_b64encode(hashlib.sha256(room_password).digest())
    cipher = Fernet(key)

    server_ip = input("🌐 Enter Server IP Address: ")
    nickname = input("👤 Enter your Session Nickname: ")

    ICMP_CODE = socket.getprotobyname('icmp')

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)

    except PermissionError:
        print("❌ [CLIENT] Error: Root privileges required! Use 'sudo python3 src/client/main.py'")
        return

    print("\n🔗 Connected to the anonymous fabric. Type message and press Enter.")
    print("Traffic is encrypted and masked under standard ICMP PING.")

    threading.Thread(target=listen_servers_pongs, args=(client_socket, cipher, server_ip), daemon=True).start()

    packet_id = 54321
    sequence = 0

    try:
        while True:
            text = input()
            if text.strip():
                full_message = f"💬 [{nickname}]: {text}"

                encrypted_payload = cipher.encrypt(full_message.encode('utf-8'))

                sequence += 1
                header = struct.pack('ddHHh', 8, 0, 0, packet_id, sequence)

                client_socket.sendto(header + encrypted_payload, (server_ip, 0))

    except KeyboardInterrupt:
        print("\n🔌 Disconnected from anonymous session.")
    finally:
        client_socket.close()


if __name__ == "__main__":
    start_client()



