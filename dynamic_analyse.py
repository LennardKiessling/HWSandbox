import os
import subprocess
import pyshark
import json
from collections import defaultdict

def create_memory_dump(dump_name):
    try:
        subprocess.run(['sudo', '/home/lennard/Schreibtisch/pcileech-4.18/files/pcileech', 'dump', '-out', dump_name],
                       check=True)
        print(f"Memory dump {dump_name} created.")
    except subprocess.CalledProcessError as e:
        print(f"Error creating memory dump {dump_name}: {e}")


def analyze_memory_dump(dump_name, output_dir, times, plugins):

    for plugin in plugins:
        output_file = os.path.join(output_dir, f"{plugin}_{times}.json")
        try:
            with open(output_file, 'w') as f:
                subprocess.run(
                    ['python3', '/home/lennard/Volatility/volatility3/vol.py', '-r', 'json', '-f', dump_name, plugin],
                    check=True,
                    stdout=f
                )
            print(f"Memory dump {dump_name} analyzed with Volatility ({plugin}). Output saved to {output_file}.")
        except subprocess.CalledProcessError as e:
            print(f"Error analyzing memory dump {dump_name} with {plugin}: {e}")


def run_pcileech():
    # Pfad zu pcileech
    pcileech_dump = "/home/lennard/Schreibtisch/pcileech-4.18/files/pcileech dump"

    try:
        # Führe das Programm aus
        result = subprocess.run([pcileech_dump], capture_output=True, text=True, check=True)

        # Gib die Standardausgabe und Fehlerausgabe aus
        print("Standardausgabe:\n", result.stdout)
        print("Fehlerausgabe:\n", result.stderr)

    except subprocess.CalledProcessError as e:
        print(f"Fehler bei der Ausführung von {pcileech_dump}: {e}")
        print("Fehlerausgabe:\n", e.stderr)

def analyze_pcap(pcap_file, malware_name):
    # Definiere die Sandbox-IP, die durch "Sandbox" ersetzt werden soll
    sandbox_ip = "192.168.2.132"

    # Öffne die PCAP-Datei
    cap = pyshark.FileCapture(pcap_file)

    # Sets zur Speicherung einzigartiger HTTP-Anfragen
    http_requests_set = set()

    # Dictionary zur Speicherung der Verbindungen und Traffic (pro Verbindung)
    connections_dict = defaultdict(lambda: {'upload': 0, 'download': 0, 'domains': set()})

    # Dictionary zur Speicherung der DNS-Anfragen nach Domain
    dns_requests_dict = defaultdict(set)

    # Listen für die eindeutigen Ausgabe-Daten
    http_requests = []

    # Durchlaufe jedes Paket in der PCAP-Datei
    for packet in cap:
        # HTTP Requests identifizieren
        if 'HTTP' in packet:
            source_ip = "Sandbox" if packet.ip.src == sandbox_ip else packet.ip.src
            destination_ip = "Sandbox" if packet.ip.dst == sandbox_ip else packet.ip.dst
            packet_length = int(packet.length) if hasattr(packet, 'length') else 0

            # Erfasse HTTP Content-Type und Content-Length
            content_type = packet.http.content_type if hasattr(packet.http, 'content_type') else None
            content_length = int(packet.http.content_length) if hasattr(packet.http, 'content_length') else None
            http_method = packet.http.request_method if hasattr(packet.http, 'request_method') else None
            http_host = packet.http.host if hasattr(packet.http, 'host') else None
            http_uri = packet.http.request_uri if hasattr(packet.http, 'request_uri') else None

            # Erkennen, ob es sich um Upload oder Download handelt
            direction = "Upload" if source_ip == "Sandbox" else "Download"

            # HTTP-Info als Tupel zur Duplikaterkennung
            http_info_no_timestamp = (source_ip, destination_ip, http_method, http_host, http_uri)

            # Wenn nicht schon vorhanden, hinzufügen
            if http_info_no_timestamp not in http_requests_set:
                http_requests_set.add(http_info_no_timestamp)
                http_requests.append({
                    'timestamp': packet.sniff_time.isoformat(),
                    'source_ip': source_ip,
                    'destination_ip': destination_ip,
                    'http_method': http_method,
                    'http_host': http_host,
                    'http_uri': http_uri,
                    'content_type': content_type,
                    'content_length': content_length,
                    'packet_length': packet_length,
                    'direction': direction
                })

        # TCP/UDP Verbindungen identifizieren (Traffic pro Verbindung erfassen)
        if hasattr(packet, 'ip'):
            source_ip = "Sandbox" if packet.ip.src == sandbox_ip else packet.ip.src
            destination_ip = "Sandbox" if packet.ip.dst == sandbox_ip else packet.ip.dst
            packet_length = int(packet.length) if hasattr(packet, 'length') else 0

            # Symmetrische Verbindungen berücksichtigen (A -> B ist das gleiche wie B -> A)
            connection_key = tuple(sorted([source_ip, destination_ip]))

            # Upload (von source_ip zu destination_ip) und Download (von destination_ip zu source_ip) erfassen
            if connection_key[0] == source_ip:
                connections_dict[connection_key]['upload'] += packet_length
            else:
                connections_dict[connection_key]['download'] += packet_length

        # DNS Requests identifizieren und nach Domain zusammenfassen
        if 'DNS' in packet and hasattr(packet.dns, 'qry_name'):
            query_name = packet.dns.qry_name
            response_ip = packet.dns.a if hasattr(packet.dns, 'a') else None

            # Füge die Antwort-IP zur Liste der IPs für diese Domain hinzu, wenn sie vorhanden ist
            if response_ip:
                dns_requests_dict[query_name].add(response_ip)

                # Verknüpfe die Domain mit der entsprechenden Verbindung
                for connection_key in connections_dict:
                    if response_ip in connection_key:
                        connections_dict[connection_key]['domains'].add(query_name)

    cap.close()

    # Konvertiere die Sets in Listen und bereite die Verbindungen für die JSON-Datei auf
    connections = []
    for connection_key, data in connections_dict.items():
        connections.append({
            'source_ip': connection_key[0],
            'destination_ip': connection_key[1],
            'upload': data['upload'],  # Traffic von source_ip zu destination_ip
            'download': data['download'],  # Traffic von destination_ip zu source_ip
            'domains': list(data['domains'])  # Zugehörige Domains
        })

    dns_requests = [{'domain': domain, 'response_ips': list(ips)} for domain, ips in dns_requests_dict.items()]

    # Verzeichnisse erstellen, falls sie nicht existieren
    output_dir = f'/media/lennard/Analyse Dateien/{malware_name}/traffic_report'
    os.makedirs(output_dir, exist_ok=True)

    # Speichere die Daten in separaten JSON-Dateien
    with open(f'{output_dir}/http_requests.json', 'w') as http_file:
        json.dump(http_requests, http_file, indent=4)

    with open(f'{output_dir}/connections.json', 'w') as conn_file:
        json.dump(connections, conn_file, indent=4)

    with open(f'{output_dir}/dns_requests_summary.json', 'w') as dns_file:
        json.dump(dns_requests, dns_file, indent=4)

    print('Analyse abgeschlossen und Dateien gespeichert.')