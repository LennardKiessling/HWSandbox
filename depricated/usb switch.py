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


from ssh_conn import  run_script_on_raspberry_pi, run_script_on_hiddevice


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
