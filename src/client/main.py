import socket, struct, threading, sys, hashlib, base64
from cryptography.fernet import Fernet
from src.utils import calculate_checksum, generate_anonymous_nickname

import time


def discover_server_ip() -> str:
    """Функция автообнаружения сервера в локальной сети (Умный пачечный ICMP-сканер)"""
    UDP_PORT = 55556
    print("📡 [Discovery] Scanning local network for MeshRoom server...")

    # --- 1. Узнаем свой локальный IP и базу подсети ---
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip_str = s.getsockname()[0]
        s.close()

        ip_parts = local_ip_str.split('.')
        base_subnet = '.'.join(ip_parts[:-1])  # Получим например "192.168.1"
        ip_parts[-1] = '255'
        subnet_broadcast = '.'.join(ip_parts)
    except Exception:
        subnet_broadcast = "255.255.255.255"
        base_subnet = ""
        local_ip_str = "127.0.0.1"

    # --- 2. Попытка через быструю отправку на свой же IP и шлюз роутера ---
    if base_subnet:
        print("🕵️‍♂️ [Discovery] Probing high-probability nodes first...")
        try:
            ICMP_CODE = socket.getprotobyname('icmp')
            scan_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
            scan_socket.settimeout(0.3)

            payload = b"MESHROOM_DISCOVER"
            header = struct.pack('bbHHh', 8, 0, 0, 999, 1)
            my_checksum = calculate_checksum(header + payload)
            packet = struct.pack('bbHHh', 8, 0, socket.htons(my_checksum), 999, 1) + payload

            # Приоритетные цели: твой ПК, роутер (.1), популярные адреса (.2, .3, .10, .27)
            priority_ips = [local_ip_str, f"{base_subnet}.1", f"{base_subnet}.2", f"{base_subnet}.27",
                            f"{base_subnet}.10"]

            for target_ip in priority_ips:
                try:
                    scan_socket.sendto(packet, (target_ip, 0))
                except Exception:
                    pass

            # Быстро смотрим, ответил ли кто-то из них
            start_time = time.time()
            while time.time() - start_time < 0.8:
                try:
                    recv_packet, addr = scan_socket.recvfrom(2048)
                    actual_ip = addr if isinstance(addr, tuple) else addr
                    offset = 20 if len(recv_packet) >= 28 else 0

                    icmp_header = recv_packet[offset:offset + 8]
                    if len(icmp_header) < 8: continue
                    icmp_type, _, _, _, _ = struct.unpack('bbHHh', icmp_header)

                    if icmp_type == 0 and recv_packet[offset + 8:] == payload:
                        clean_ip = actual_ip[0] if isinstance(actual_ip, tuple) else actual_ip
                        print(f"🎯 [Discovery] Found server automatically on priority node: {clean_ip}")
                        scan_socket.close()
                        return clean_ip
                except socket.timeout:
                    break
            scan_socket.close()
        except Exception:
            pass

    # --- 3. Медленный веерный обход пачками (если приоритетные цели промолчали) ---
    if base_subnet:
        print("🕵️‍♂️ [Discovery] Switching to multi-batch ICMP sweep...")
        try:
            ICMP_CODE = socket.getprotobyname('icmp')
            scan_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)

            payload = b"MESHROOM_DISCOVER"
            header = struct.pack('bbHHh', 8, 0, 0, 999, 1)
            my_checksum = calculate_checksum(header + payload)
            packet = struct.pack('bbHHh', 8, 0, socket.htons(my_checksum), 999, 1) + payload

            # Сканируем пулами по 5 адресов с микропаузой 0.05 сек, чтобы роутер не сходил с ума
            for i in range(1, 51):
                target_ip = f"{base_subnet}.{i}"
                if target_ip in priority_ips: continue  # Пропускаем то, что уже пинговали

                try:
                    scan_socket.sendto(packet, (target_ip, 0))
                except Exception:
                    pass

                if i % 5 == 0:
                    time.sleep(0.05)  # Даем роутеру передохнуть

            scan_socket.settimeout(1.0)
            start_time = time.time()
            while time.time() - start_time < 1.5:
                try:
                    recv_packet, addr = scan_socket.recvfrom(2048)
                    actual_ip = addr if isinstance(addr, tuple) else addr
                    offset = 20 if len(recv_packet) >= 28 else 0

                    icmp_header = recv_packet[offset:offset + 8]
                    if len(icmp_header) < 8: continue
                    icmp_type, _, _, _, _ = struct.unpack('bbHHh', icmp_header)

                    if icmp_type == 0 and recv_packet[offset + 8:] == payload:
                        clean_ip = actual_ip[0] if isinstance(actual_ip, tuple) else actual_ip
                        print(f"🎯 [Discovery] Found server automatically via batch sweep: {clean_ip}")
                        scan_socket.close()
                        return clean_ip
                except socket.timeout:
                    break
            scan_socket.close()
        except Exception as e:
            print(f"⚠️ [Discovery] ICMP Sweep failed: {e}")

    print("⚠️ [Discovery] Auto-discovery failed (Network Congestion).")
    return ""


def listen_servers_pongs(client_socket, cipher, server_ip):
    while True:
        try:
            packet, addr = client_socket.recvfrom(2048)
            if isinstance(addr, tuple):
                actual_ip = addr[0]
            else:
                actual_ip = addr

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
        join_text = f"📢 [{nickname}]: joined the session!"
        encrypted_join_payload = cipher.encrypt(join_text.encode('utf-8'))

        sequence += 1
        join_initial_header = struct.pack('bbHHh', 8, 0, 0, packet_id, sequence)

        join_checksum = calculate_checksum(join_initial_header + encrypted_join_payload)
        join_final_header = struct.pack('bbHHh', 8, 0, socket.htons(join_checksum), packet_id, sequence)

        client_socket.sendto(join_final_header + encrypted_join_payload, (server_ip, 0))

    except Exception as e:
        print(f"⚠️ Failed to send join notification: {e}")
    # =======================================================

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
        try:
            exit_text = f"📢 [{nickname}]: left the session!"
            encrypted_exit_payload = cipher.encrypt(exit_text.encode('utf-8'))

            sequence += 1
            exit_initial_header = struct.pack('bbHHh', 8, 0, 0, packet_id, sequence)

            exit_checksum = calculate_checksum(exit_initial_header + encrypted_exit_payload)
            exit_final_header = struct.pack('bbHHh', 8, 0, socket.htons(exit_checksum), packet_id, sequence)

            client_socket.sendto(exit_final_header + encrypted_exit_payload, (server_ip, 0))
        except Exception:
            pass

        print("\n🔌 Disconnected from anonymous session. Tracks cleared.")
    finally:
        client_socket.close()


if __name__ == "__main__":
    start_client()
