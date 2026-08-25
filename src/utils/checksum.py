import struct

def calculate_checksum(source_string: bytes) -> int:
    """
    Подсчет контрольной суммы по стандарту RFC 1071 (Internet Checksum).
    Необходим для сборки валидных ICMP (Ping) пакетов на macOS и Linux.
    """
    count_to = (int(len(source_string) / 2)) * 2
    checksum = 0
    count = 0

    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        checksum = checksum + this_val
        checksum = checksum & 0xffffffff
        count = count + 2

    if count_to < len(source_string):
        checksum = checksum + source_string[len(source_string) - 1]
        checksum = checksum & 0xffffffff

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum = checksum + (checksum >> 16)
    answer = ~checksum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer
