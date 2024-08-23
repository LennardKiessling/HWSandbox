from dynamic_analyse import *
from ssh_conn import *
from usb_data_switch import *
from usb_onoff_switch import *
from file_management import *
import json
import os
import paramiko
from dotenv import load_dotenv
from pathlib import Path
from baseline_comparison import *

def main():
    with open("/home/lennard/PycharmProjects/Switch USB/config.json", "r") as json_file:
        config = json.load(json_file)

    # Zuweisung der Variablen aus der JSON-Datei
    dotenv_path = Path(config["dotenv_path"])

    # USB On/Off Switch Control
    ip_address_usb_switch_Sandbox = config["usb_switch"]["ip_address_usb_switch_Sandbox"]

    # Raspberry Pi Power Control
    raspberry_pi_host = config["raspberry_pi_power_control"]["raspberry_pi_host"]
    raspberry_pi_port = config["raspberry_pi_power_control"]["raspberry_pi_port"]
    raspberry_pi_username = config["raspberry_pi_power_control"]["raspberry_pi_username"]
    private_key_path = config["raspberry_pi_power_control"]["private_key_path"]

    # Raspberry Pi Internet Control
    ip_traffic_pi_host = config["raspberry_internet_control"]["ip_traffic_pi_host"]
    ip_traffic_pi_port = config["raspberry_internet_control"]["ip_traffic_pi_port"]
    ip_traffic_pi_username = config["raspberry_internet_control"]["ip_traffic_pi_username"]
    ip_traffic_private_key_path = config["raspberry_internet_control"]["ip_traffic_private_key_path"]

    # HID Device Control
    hid_device_host = config["raspberry_hid_device"]["hid_device_host"]
    load_dotenv(dotenv_path=dotenv_path)
    hid_device_password = os.getenv('hidDevicePassword')

    # Erstellen eines SSH-Clients
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Scripte für die PC-Steuerung
    start_pc_script = config["scripts"]["start_pc_script"]
    pc_running_info = config["scripts"]["pc_running_info"]
    shutoff_pc_script = config["scripts"]["shutoff_pc_script"]

    # Malware Directory
    directory = config["malware_dir"]

    # Standard-Switch und Prozessinfo
    default_switch = config["default_switch"]
    switch_location = config["switch_location"]
    process_info = config["process_info"]

    # Anzahl der Dumps
    dump_count = config["dump_count"]

    # Plugins von Volatility
    plugins = config["plugins"]

    # Baseline Folder
    baseline_dir = config["baseline_folder"]

    # Analyse Paths
    analyse_base_path = config["analyse_base_path"]

    traffic_path = config["analyse_paths"]["traffic_path"]
    data_integrity_baseline_path = config["analyse_paths"]["data_integrity_path"]
    votality_path = config["analyse_paths"]["votality_dump"]

    traffic_connections_file = config["analyse_paths"]["traffic"]["connections"]
    traffic_dns_requests_file = config["analyse_paths"]["traffic"]["dns-requests"]
    traffic_http_requests_file = config["analyse_paths"]["traffic"]["http-requests"]
    data_integrity_registry_file = config["analyse_paths"]["data_integrity"]["registry"]
    data_integrity_user_data_file = config["analyse_paths"]["data_integrity"]["user_data"]

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

            run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username,
                                       ip_traffic_private_key_path,
                                       "sudo systemctl start limit_kb.service")
            run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username,
                                       ip_traffic_private_key_path,
                                       "sudo systemctl stop limit_kb.service")

            # Sandbox wird auf Windows gestartet
            run_script_on_raspberry_pi(raspberry_pi_host, raspberry_pi_port, raspberry_pi_username, private_key_path,
                                       start_pc_script)
            time.sleep(10)

            # raspberry hiddevice hochfahren
            USB_Sandbox_ON(ip_address_usb_switch_Sandbox)
            time.sleep(30)

            # Traffic Aufzeichnung und 500kb Regel starten
            # run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username, ip_traffic_private_key_path,
            #                           "sudo systemctl start limit_kb.service")
            run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username,
                                       ip_traffic_private_key_path,
                                       "sudo systemctl start record_traffic.service")

            # Maus & Tastatur werden ausgeführt -> Malware wird gestartet
            run_script_on_hiddevice(hid_device_host, raspberry_pi_port, raspberry_pi_username, hid_device_password,
                                    "sudo python3 hidinput.py")

            # memory dump mit pcileech

            for i in range(dump_count):
                dump_name = f"/media/lennard/Analyse Dateien/{malware_name}/raw/raw_{i}.bin"
                create_memory_dump(dump_name)

            # raspberry hiddevice runterfahren
            run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username,
                                       ip_traffic_private_key_path,
                                       "sudo systemctl stop limit_kb.service")
            run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username,
                                       ip_traffic_private_key_path,
                                       "sudo systemctl stop record_traffic.service")
            run_script_on_hiddevice(hid_device_host, raspberry_pi_port, raspberry_pi_username, hid_device_password,
                                    "sudo shutdown now")

            time.sleep(10)
            USB_Sandbox_OFF(ip_address_usb_switch_Sandbox)
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


            move_file(differences_registry_json, data_integrity_path)

            move_file(differences_userdata_json, data_integrity_path)

            # Get the PCAP File
            run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username,
                                       ip_traffic_private_key_path, "data_get", malware_name=malware_name)

            # Beispielaufruf der Funktion
            pcap_file = f"/media/lennard/Analyse Dateien/{malware_name}/traffic_report/network_traffic.pcap"

            analyze_pcap(pcap_file, malware_name=malware_name)

            # Analyze Mem Dump
            for i in range(dump_count):
                output_dir = f"/media/lennard/Analyse Dateien/{malware_name}/analysed/"
                dump_name = f"/media/lennard/Analyse Dateien/{malware_name}/raw/raw_{i}.bin"
                analyze_memory_dump(dump_name, output_dir, times=i, plugins=plugins)


            # Baseline comparison

            baseline_comparison( f"{analyse_base_path}{baseline_dir}{traffic_path}{traffic_connections_file}",
                                f"{analyse_base_path}{malware_name}{traffic_path}{traffic_connections_file}",
                                f'{analyse_base_path}{malware_name}{traffic_path}nullified_connections.json')

            baseline_comparison( f"{analyse_base_path}{baseline_dir}{traffic_path}{traffic_http_requests_file}",
                                f"{analyse_base_path}{malware_name}{traffic_path}{traffic_http_requests_file}",
                                f'{analyse_base_path}{malware_name}{traffic_path}nullified_http_requests.json')

            baseline_comparison( f"{analyse_base_path}{baseline_dir}{traffic_path}{traffic_dns_requests_file}",
                                f"{analyse_base_path}{malware_name}{traffic_path}{traffic_dns_requests_file}",
                                f'{analyse_base_path}{malware_name}{traffic_path}nullified_dns_requests.json')

            baseline_comparison(f"{analyse_base_path}{baseline_dir}{data_integrity_baseline_path}{data_integrity_registry_file}",
                                f"{analyse_base_path}{malware_name}{data_integrity_baseline_path}{data_integrity_registry_file}",
                                f'{analyse_base_path}{malware_name}{data_integrity_baseline_path}nullified_differences_registry_file_hashes.json')

            baseline_comparison(f"{analyse_base_path}{baseline_dir}{data_integrity_baseline_path}{data_integrity_user_data_file}",
                                f"{analyse_base_path}{malware_name}{data_integrity_baseline_path}{data_integrity_user_data_file}",
                                f'{analyse_base_path}{malware_name}{data_integrity_baseline_path}nullified_differences_userdata_file_hashes.json')

            for plugin in plugins:
                for i in range(dump_count):
                    baseline_comparison(
                        f"{analyse_base_path}{baseline_dir}{votality_path}/{plugin}_{i}.json",
                        f"{analyse_base_path}{malware_name}{votality_path}/{plugin}_{i}.json",
                        f'{analyse_base_path}{malware_name}{votality_path}/nullified_{plugin}_{i}.json')



        else:
            print(f"Es gibt keine Dateien in {directory}.")
            # Pro Minute ein Check ob neue Datei
            time.sleep(60)

if __name__ == "__main__":
    main()