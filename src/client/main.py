import socket, struct, threading, sys, hashlib, base64
from cryptography.fernet import Fernet
from src.utils import calculate_checksum, generate_anonymous_nickname


def discover_server_ip() -> str:
    """Функция автообнаружения сервера в локальной сети через UDP Broadcast (фикс опечаток)"""
    UDP_PORT = 55556
    print("📡 [Discovery] Scanning local network for MeshRoom server...")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp_socket.settimeout(2.0)

    try:
        # Узнаем свой локальный IP-адрес
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip_str = s.getsockname()[0]
        s.close()

        ip_parts = local_ip_str.split('.')
        ip_parts[-1] = '255'
        subnet_broadcast = '.'.join(ip_parts)
    except Exception:
        subnet_broadcast = "255.255.255.255"

    try:
        # Отправляем сигналы по всем направлениям (включая локалхост для теста)
        targets = [subnet_broadcast, "255.255.255.255", "127.0.0.1"]
        for target in targets:
            try:
                udp_socket.sendto(b"MESHROOM_DISCOVER", (target, UDP_PORT))
            except Exception:
                pass

        # Ждем ответ от сервера
        data, addr = udp_socket.recvfrom(1024)
        if data == b"MESHROOM_HERE":
            # ИСПРАВЛЕНО: извлекаем строку IP-адреса из кортежа addr
            server_ip = addr[0]

            # Если сервер ответил с локалхоста, подменяем на реальный IP для ICMP
            if server_ip == "127.0.0.1":
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    server_ip = s.getsockname()[0]
                    s.close()
                except Exception:
                    pass

            print(f"🎯 [Discovery] Found server automatically at: {server_ip}")
            return server_ip

    except socket.timeout:
        print("⚠️ [Discovery] Auto-discovery timeout. Server not found.")
    except Exception as e:
        print(f"⚠️ [Discovery] Scan error: {e}")
    finally:
        udp_socket.close()

    return ""


def listen_servers_pongs(client_socket, cipher, server_ip):
    while True:
        try:
            packet, addr = client_socket.recvfrom(2048)
            actual_ip = addr if isinstance(addr, tuple) else addr

            if actual_ip == server_ip:
                offset = 20 if len(packet) >= 28 else 0
                icmp_header = packet[offset:offset + 8]

                if len(icmp_header) < 8:
                    continue

                icmp_type, code, checksum, packet_id, sequence = struct.unpack('bbHHh', icmp_header)

                if icmp_type == 0:
                    payload = packet[offset + 8:]

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


    server_ip = discover_server_ip()

    # Если автопоиск не сработал (например, фаервол заблокировал UDP), даем ввести вручную как резервный вариант
    if not server_ip:
        while True:
            server_ip = input("🌐 Enter Server IP Address manually: ").strip()
            if server_ip:
                break
            print("❌ IP address cannot be empty! Please try again.")

    nickname = generate_anonymous_nickname()
    print(f"😎 Your anonymity mask for this session: {nickname}\n")

    ICMP_CODE = socket.getprotobyname('icmp')

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
    except PermissionError:
        print("❌ [CLIENT] Error: Root privileges required! Use 'sudo python3 -m src.client.main'")
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

                initial_header = struct.pack('bbHHh', 8, 0, 0, packet_id, sequence)
                my_checksum = calculate_checksum(initial_header + encrypted_payload)

                final_header = struct.pack('bbHHh', 8, 0, socket.htons(my_checksum), packet_id, sequence)

                client_socket.sendto(final_header + encrypted_payload, (server_ip, 0))

    except KeyboardInterrupt:
        print("\n🔌 Disconnected from anonymous session.")
    finally:
        client_socket.close()


if __name__ == "__main__":
    start_client()
