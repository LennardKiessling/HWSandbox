import serial
from pathlib import Path
import serial.tools.list_ports
import os
import shutil
import subprocess
import paramiko
import re
from dotenv import load_dotenv
import requests
import time
import pickle
import pyshark
import json
from collections import defaultdict



dotenv_path = Path('/home/lennard/PycharmProjects/Switch USB/.venv/.env')

# Controlladresses Delock USB ON/OFF
ip_address_usb_switch_Sandbox_TOGGLE = "http://192.168.1.128/cm?cmnd=Power%20TOGGLE"
ip_address_usb_switch_Sandbox_ON = "http://192.168.1.128/cm?cmnd=Power%20ON"
ip_address_usb_switch_Sandbox_OFF = "http://192.168.1.128/cm?cmnd=Power%20off"


# Raspberry PC Power Control
raspberry_pi_host = "192.168.1.108"
raspberry_pi_port = 22
raspberry_pi_username = "lennard"
private_key_path = '/home/lennard/pi-ba'

# Raspberry Internet Control + Traffic Analyse
ip_traffic_pi_host = "192.168.1.230"
ip_traffic_pi_port = 22
ip_traffic_pi_username = "lennard"
ip_traffic_private_key_path = '/home/lennard/.ssh/id_rsa'


# Raspberry HID Device (Maus Tastatur)
hid_device_host = "192.168.1.245"
load_dotenv(dotenv_path=dotenv_path)
hid_device_password = os.getenv('hidDevicePassword')


# Erstellen eines SSH-Clients
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())


# Scripte Controll PC
start_pc_script = "/home/lennard/PycharmProjects/raspberrypi/startpc.py"
pc_running_info = "/home/lennard/PycharmProjects/raspberrypi/checkrunningpc.py"
shutoff_pc_script = "/home/lennard/PycharmProjects/raspberrypi/shutoffpc.py"


dump_count = 3

# Malware dir
directory = "/home/lennard/PycharmProjects/Switch USB/malware"

default_switch = "analyse"

switch_location = default_switch

process_info = "ready"


def txt_to_set(file_path):
    """
    Liest eine Textdatei ein und erstellt ein Set mit den MD5-Hashes.

    :param file_path: Pfad zur Textdatei, die die MD5-Hashes enthält
    :return: Ein Set mit den MD5-Hashes
    """
    with open(file_path, "r") as file:
        md5_set = {line.strip() for line in file}
    return md5_set


def save_set_to_pickle(md5_set, pickle_path):
    """
    Speichert ein Set mithilfe von pickle in einer Datei.

    :param md5_set: Das zu speichernde Set
    :param pickle_path: Pfad zur Pickle-Datei, in der das Set gespeichert wird
    """
    with open(pickle_path, 'wb') as file:
        pickle.dump(md5_set, file)
    print(f"Set erfolgreich in {pickle_path} gespeichert.")


def load_set_from_pickle(pickle_path):
    """
    Lädt ein Set aus einer Pickle-Datei.

    :param pickle_path: Pfad zur Pickle-Datei
    :return: Das geladene Set
    """
    with open(pickle_path, 'rb') as file:
        md5_set = pickle.load(file)
    return md5_set


# Beispielpfade (Diese kannst du an deine Bedürfnisse anpassen)
txt_file_path = "/home/lennard/PycharmProjects/Switch USB/md5_malware_hashes/full_md5.txt"  # Pfad zur Textdatei
pickle_file_path = "/home/lennard/PycharmProjects/Switch USB/md5_malware_hashes/hashes.pkl"  # Pfad zur Pickle-Datei

# Erstellen des Sets aus der Textdatei
#md5_set = txt_to_set(txt_file_path)

# Speichern des Sets mit pickle
#save_set_to_pickle(md5_set, pickle_file_path)

"""
Hier könnte noch Integration kommen mit -> 48 Stunden neueste Daten abrufen und hinzufügen zum Set
"""

hash_set_loaded = load_set_from_pickle(pickle_file_path)

def USB_Sandbox_ON():
    try:
        response = requests.get(ip_address_usb_switch_Sandbox_ON)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"An error occurred with USB switch: {e}")


def USB_Sandbox_OFF():
    try:
        response = requests.get(ip_address_usb_switch_Sandbox_OFF)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"An error occurred with USB switch: {e}")


def USB_Sandbox_Toggle():
    try:
        response = requests.get(ip_address_usb_switch_Sandbox_TOGGLE)
        response.raise_for_status()
        if response.status_code == 200:
            return response.text
    except requests.exceptions.RequestException as e:
        print(f"An error occurred with USB switch: {e}")

def unmount_device(device):
    try:
        result = subprocess.run(["lsblk", "-o", "MOUNTPOINT", "-nr", device], check=True, capture_output=True, text=True)
        if result.stdout.strip():
            subprocess.run(["sudo", "umount", device], check=True)
            print(f"{device} erfolgreich unmounted.")
        else:
            print(f"{device} ist nicht gemountet.")
    except subprocess.CalledProcessError as e:
        print(f"Fehler beim Überprüfen/Unmounten des Geräts: {e}")

def create_memory_dump(dump_name):
    try:
        subprocess.run(['sudo', '/home/lennard/Schreibtisch/pcileech-4.18/files/pcileech', 'dump', '-out', dump_name],
                       check=True)
        print(f"Memory dump {dump_name} created.")
    except subprocess.CalledProcessError as e:
        print(f"Error creating memory dump {dump_name}: {e}")


def analyze_memory_dump(dump_name, output_dir):
    plugins = [
        'windows.pslist'
    ]

    base_output_name = os.path.basename(dump_name).replace('.bin', '')

    for plugin in plugins:
        output_file = os.path.join(output_dir, f"{base_output_name}_{plugin}.json")
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

def run_script_on_hiddevice(host, port, username, password, command):
    # Erstelle ein SSH-Client-Objekt
    client = paramiko.SSHClient()
    # Automatisch unbekannte Schlüssel akzeptieren
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Verbinde mit dem HID-Gerät
        client.connect(hostname=host, port=port, username=username, password=password, pkey=None)
        print("Verbindung hergestellt")

        # Führe den Befehl aus
        stdin, stdout, stderr = client.exec_command(command, get_pty=True)
        print("Befehl wird ausgeführt...")

        # Lese die Ausgabe Zeile für Zeile
        while True:
            line = stdout.readline()
            if not line:
                break
            print(line, end='')  # Ausgabe der Zeile auf der Konsole

    except Exception as e:
        print(f"Verbindung fehlgeschlagen: {e}")

    finally:
        # Schließen der SSH-Verbindung
        print("Verbindung geschlossen")
        client.close()

def run_script_on_raspberry_pi(host, port, username, private_key_path, script_path):
    # Erstelle ein SSH-Client-Objekt
    client = paramiko.SSHClient()
    # Automatisch unbekannte Schlüssel akzeptieren
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Laden des Private Keys
    private_key = paramiko.RSAKey(filename=private_key_path)

    try:

        # Verbinde mit dem Raspberry Pi
        client.connect(hostname=host, port=port, username=username, pkey=private_key)
        print("Verbindung hergestellt")

        if host == ip_traffic_pi_host:
            if script_path == "data_get":
                # SFTP-Sitzung starten
                sftp = client.open_sftp()

                remote_traffic_report_path = "/var/log/network_traffic.pcap"
                local_traffic_path_path = (f"/media/lennard/Analyse Dateien/{malware_name}/traffic_report/network_traffic.pcap")

                # Traffic von Pi runterladen
                sftp.get(remote_traffic_report_path, local_traffic_path_path)
                print(f"Die Datei wurde erfolgreich heruntergeladen nach {local_traffic_path_path}")

                # SFTP-Sitzung schließen
                sftp.close()
            else:
                client.exec_command(script_path)
                print("Script wird ausgeführt...")
        else:
            # Wenn das Script spezifisch ist
            if script_path == pc_running_info:
                # Führe das Script aus
                stdin, stdout, stderr = client.exec_command(f'python3 {script_path}', get_pty=True)
                print("Script wird ausgeführt...")
                # Lese die Ausgabe Zeile für Zeile
                while True:
                    # Lese eine Zeile der Standardausgabe
                    line = stdout.readline()
                    if not line:
                        print("not line")
                        break
                    print(line, end='')  # Ausgabe der Zeile auf der Konsole
                    # Überprüfe, ob die Zeile "off" enthält
                    if "off" in line:
                        print("Das Script hat 'off' zurückgegeben. Beende die Schleife.")
                        break
            else:
                client.exec_command(f'python3 {script_path}')
                print("Script wird ausgeführt...")


    except Exception as e:
        print(f"Verbindung fehlgeschlagen: {e}")

    finally:
        # Schließen der SSH-Verbindung
        print("Verbindung geschlossen")
        client.close()


def switch_usb(location):
    # Seriellen Port öffnen
    ser = serial.Serial('/dev/ttyUSB0', 9600, timeout=0.1)

    if ser.is_open:
        print("Öffnen erfolgreich")
        print(ser.name)
    else:
        print("Öffnen fehlgeschlagen")

    # Befehle senden
    ser.write(b'AT+CH1=1')  # Relay ON
    time.sleep(1)
    ser.write(b'AT+CH1=0')  # Relay OFF

    # Seriellen Port schließen
    ser.close()
    print("Serieller Port geschlossen")
    if location == "analyse":
        switch_location = "sandbox"
        return switch_location
    else:
        switch_location = "analyse"
        return switch_location


def check_disk_connected():
    return os.path.exists('/media/lennard/37728ca4-0882-43f0-90ef-cf3374115e25/home/lk-switch-linux/Dokumente/malware')

def sanitize_filename(filename):
    sanitized_filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
    return sanitized_filename


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


def create_malware_dir(malware_name):
    # Hauptverzeichnis erstellen
    main_dir = f"/media/lennard/Analyse Dateien/{malware_name}"
    os.mkdir(main_dir, mode=0o777)

    # Unterverzeichnisse erstellen
    subdirs = ['raw', 'analysed', 'data_integrity_report', 'traffic_report']
    for subdir in subdirs:
        os.mkdir(os.path.join(main_dir, subdir), mode=0o777)



while True:

    files = os.listdir(directory)

    # Filtern, um nur Dateien zu erhalten
    files = [f for f in files if os.path.isfile(os.path.join(directory, f))]

    if files:


        # Anfang Durchlauf
        if not check_disk_connected():
            print("Nicht mit Analyse connected")
            switch_location = "sandbox"
            switch_location = switch_usb(switch_location)
            print(switch_location)
            time.sleep(5)

        print(f"Es gibt Dateien in {directory}.")

        source = f"{directory}/{files[0]}"

        malware_name = sanitize_filename(files[0])
        create_malware_dir(malware_name)

        destination = "/media/lennard/37728ca4-0882-43f0-90ef-cf3374115e25/home/lk-switch-linux/PycharmProjects/RestoreBackup/malware/"

        try:
            shutil.move(source, destination)
            print(f"Datei wurde nach {destination} (ext. SSD) verschoben.")
            time.sleep(5)
            os.sync()
            unmount_device("/dev/sdc")
        except FileNotFoundError as e:
            print(f"Fehler: Die Datei oder das Verzeichnis wurde nicht gefunden. ({e})")
            break
        except PermissionError as e:
            print(f"Fehler: Berechtigung verweigert. ({e})")
            break
        except Exception as e:
            print(f"Ein unerwarteter Fehler ist aufgetreten: {e}")
            break

        

        # Switch auf Sandbox
        switch_location = switch_usb(switch_location)
        print(switch_location)
        time.sleep(10)

        # Verbindung mit Pi um Sandbox zu starten
        run_script_on_raspberry_pi(raspberry_pi_host, raspberry_pi_port, raspberry_pi_username, private_key_path,
                                   start_pc_script)

        # Warten das Malware übertragen wurde und Sandbox wieder runtergefahren ist
        run_script_on_raspberry_pi(raspberry_pi_host, raspberry_pi_port, raspberry_pi_username, private_key_path,
                                   pc_running_info)


        # Sandbox auf Analyse (2tes mal)
        switch_location = switch_usb(switch_location)
        print(switch_location)
        time.sleep(5)

        run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username, ip_traffic_private_key_path,
                                   "sudo systemctl start limit_kb.service")
        run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username, ip_traffic_private_key_path,
                                   "sudo systemctl stop limit_kb.service")

        # Sandbox wird auf Windows gestartet
        run_script_on_raspberry_pi(raspberry_pi_host, raspberry_pi_port, raspberry_pi_username, private_key_path,
                                   start_pc_script)
        time.sleep(10)

        #raspberry hiddevice hochfahren
        USB_Sandbox_ON()
        time.sleep(30)

        # Traffic Aufzeichnung und 500kb Regel starten
        #run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username, ip_traffic_private_key_path,
        #                           "sudo systemctl start limit_kb.service")
        run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username, ip_traffic_private_key_path,
                                   "sudo systemctl start record_traffic.service")

        # Maus & Tastatur werden ausgeführt -> Malware wird gestartet
        run_script_on_hiddevice(hid_device_host, raspberry_pi_port, raspberry_pi_username, hid_device_password, "sudo python3 hidinput.py")


        # memory dump mit pcileech

        for i in range(dump_count):
            dump_name = f"/media/lennard/Analyse Dateien/{malware_name}/raw/raw_{i}.bin"
            create_memory_dump(dump_name)

        #raspberry hiddevice runterfahren
        run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username, ip_traffic_private_key_path,
                                   "sudo systemctl stop limit_kb.service")
        run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username, ip_traffic_private_key_path,
                                   "sudo systemctl stop record_traffic.service")
        run_script_on_hiddevice(hid_device_host, raspberry_pi_port, raspberry_pi_username, hid_device_password, "sudo shutdown now")

        time.sleep(10)
        USB_Sandbox_OFF()
        run_script_on_raspberry_pi(raspberry_pi_host, raspberry_pi_port, raspberry_pi_username, private_key_path,
                                   shutoff_pc_script)

        # Switch auf Sandbox umschalten
        time.sleep(5)
        switch_location = switch_usb(switch_location)
        print(switch_location)
        time.sleep(5)

        # Pc mit Ubuntu starten um Datenträgeranalyse zu beginnen
        run_script_on_raspberry_pi(raspberry_pi_host, raspberry_pi_port, raspberry_pi_username, private_key_path,
                                   start_pc_script)

        # Check ob Registry fertig ist
        run_script_on_raspberry_pi(raspberry_pi_host, raspberry_pi_port, raspberry_pi_username, private_key_path,
                                   pc_running_info)


        # Switch auf Analyse umschalten
        time.sleep(5)
        switch_location = switch_usb(switch_location)
        print(switch_location)
        time.sleep(5)

        differences_registry_json = '/media/lennard/37728ca4-0882-43f0-90ef-cf3374115e25/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/differences_registry_file_hashes.json'
        differences_userdata_json = '/media/lennard/37728ca4-0882-43f0-90ef-cf3374115e25/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/differences_userdata_file_hashes.json'

        data_integrity_path = f'/media/lennard/Analyse Dateien/{malware_name}/data_integrity_report'

        try:
            shutil.move(differences_registry_json, data_integrity_path)
            print(f"Datei wurde nach {destination} (ext. SSD) verschoben.")
            time.sleep(5)
            os.sync()
            unmount_device("/dev/sdc")
        except FileNotFoundError as e:
            print(f"Fehler: Die Datei oder das Verzeichnis wurde nicht gefunden. ({e})")
            break
        except PermissionError as e:
            print(f"Fehler: Berechtigung verweigert. ({e})")
            break
        except Exception as e:
            print(f"Ein unerwarteter Fehler ist aufgetreten: {e}")
            break

        try:
            shutil.move(differences_userdata_json, data_integrity_path)
            print(f"Datei wurde nach {destination} (ext. SSD) verschoben.")
            time.sleep(5)
            os.sync()
            unmount_device("/dev/sdc")
        except FileNotFoundError as e:
            print(f"Fehler: Die Datei oder das Verzeichnis wurde nicht gefunden. ({e})")
            break
        except PermissionError as e:
            print(f"Fehler: Berechtigung verweigert. ({e})")
            break
        except Exception as e:
            print(f"Ein unerwarteter Fehler ist aufgetreten: {e}")
            break

        # Get the PCAP File
        run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username, ip_traffic_private_key_path, "data_get")

        # Beispielaufruf der Funktion
        pcap_file = f"/media/lennard/Analyse Dateien/{malware_name}/traffic_report/network_traffic.pcap"

        analyze_pcap(pcap_file, malware_name=malware_name)

        # Analyze Mem Dump
        for i in range(dump_count):
            output_dir = f"/media/lennard/Analyse Dateien/{malware_name}/analysed/"
            dump_name = f"/media/lennard/Analyse Dateien/{malware_name}/raw/raw_{i}.bin"
            analyze_memory_dump(dump_name, output_dir)


    else:
        print(f"Es gibt keine Dateien in {directory}.")
        # Pro Minute ein Check ob neue Datei
        time.sleep(60)
