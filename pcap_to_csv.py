import math
import pandas as pd
from scapy.all import PcapReader, IP, IPv6, TCP, UDP
import os

def calculate_entropy(data_bytes):
    """
    Расчет энтропии Шеннона для полезной нагрузки (Payload).
    Логика 1-в-1 совпадает с функцией calculate_entropy на Rust.
    """
    if not data_bytes:
        return 0.0
    
    entropy = 0.0
    length = len(data_bytes)
    
    for x in range(256):
        p_x = data_bytes.count(x) / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
            
    return float(entropy)

def process_pcap(input_file, output_file, label=0):
    """
    Конвертация PCAP в CSV, совместимый с Aegis AI.
    """
    print(f"[*] Открываем дамп трафика: {input_file}...")
    data_list = []
    prev_time = None

    # PcapReader читает пакеты по одному, не загружая весь файл в RAM
    with PcapReader(input_file) as pcap:
        for i, pkt in enumerate(pcap):
            # Пропускаем всё, что не является IP-трафиком (например, ARP)
            if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                continue

            # 1. Packet Length (Длина всего фрейма)
            packet_len = len(pkt)

            # 2. IAT (Inter-Arrival Time в секундах)
            current_time = float(pkt.time)
            iat = current_time - prev_time if prev_time is not None else 0.0
            prev_time = current_time

            # Инициализация дефолтных значений для L4
            dest_port = 0
            tcp_flags = 0
            payload_bytes = b""

            # 3. Разбор Transport Layer (L4)
            if pkt.haslayer(TCP):
                dest_port = int(pkt[TCP].dport)
                # Флаги Scapy совпадают с битовой маской Rust 
                # (FIN=1, SYN=2, RST=4, PSH=8, ACK=16, URG=32)
                tcp_flags = int(pkt[TCP].flags) 
                payload_bytes = bytes(pkt[TCP].payload) # Только данные приложения
                
            elif pkt.haslayer(UDP):
                dest_port = int(pkt[UDP].dport)
                payload_bytes = bytes(pkt[UDP].payload)

            # 4. Расчет энтропии
            entropy = calculate_entropy(payload_bytes)

            # 5. Сборка вектора
            data_list.append({
                'packet_len': packet_len,
                'iat': iat,
                'entropy': entropy,
                'tcp_flags': tcp_flags,
                'dest_port': dest_port,
                'label': label
            })

            # Логирование прогресса
            if i > 0 and i % 5000 == 0:
                print(f"  > Обработано пакетов: {i}")

    # Создание DataFrame
    df = pd.DataFrame(data_list)
    
    # ЖЕСТКАЯ ФИКСАЦИЯ ПОРЯДКА КОЛОНОК
    # Это гарантирует, что структура всегда совпадает с self.features в online.py
    columns_order = ['packet_len', 'iat', 'entropy', 'tcp_flags', 'dest_port', 'label']
    
    # Если дамп был абсолютно пустым (ни одного IP пакета)
    if df.empty:
        df = pd.DataFrame(columns=columns_order)
    else:
        df = df[columns_order]
    
    # Безопасное сохранение
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    df.to_csv(output_file, index=False)
    
    print(f"[+] Операция успешна. Векторы сохранены в {output_file}")
    print(f"[+] Всего извлечено строк: {len(df)}")

if __name__ == "__main__":
    # Твой дамп из общаги (мирный трафик)
    INPUT_PCAP = "data/pcap/peaceful_life.pcap" 
    # Куда положить готовый CSV
    OUTPUT_CSV = "data/datasets/my_benign_traffic.csv"
    
    if os.path.exists(INPUT_PCAP):
        # Метка 0 означает Benign (Норма)
        process_pcap(INPUT_PCAP, OUTPUT_CSV, label=0)
    else:
        print(f"[!] Файл {INPUT_PCAP} не найден в текущей директории.")