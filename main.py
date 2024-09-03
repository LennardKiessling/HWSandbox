import time

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
import threading

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
                time.sleep(2)

            print(f"Es gibt Dateien in {directory}.")

            source = f"{directory}/{files[0]}"

            malware_name = sanitize_filename(files[0])
            create_malware_dir(malware_name)

            destination = "/media/lennard/37728ca4-0882-43f0-90ef-cf3374115e25/home/lk-switch-linux/PycharmProjects/RestoreBackup/malware/"

            try:
                shutil.move(source, destination)
                print(f"Datei wurde nach {destination} (ext. SSD) verschoben.")
                time.sleep(2)
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
            time.sleep(3)

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
            time.sleep(1)
            run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username,
                                       ip_traffic_private_key_path,
                                       "sudo systemctl stop limit_kb.service")

            # Sandbox wird auf Windows gestartet
            run_script_on_raspberry_pi(raspberry_pi_host, raspberry_pi_port, raspberry_pi_username, private_key_path,
                                       start_pc_script)
            time.sleep(10)

            # raspberry hiddevice hochfahren
            USB_Sandbox_ON(ip_address_usb_switch_Sandbox)
            time.sleep(40)

            # Traffic Aufzeichnung und 500kb Regel starten
            # run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username, ip_traffic_private_key_path,
            #                           "sudo systemctl start limit_kb.service")
            run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username,
                                       ip_traffic_private_key_path,
                                       "sudo systemctl start record_traffic.service")

            # Maus & Tastatur werden ausgeführt -> Malware wird gestartet
            run_script_on_hiddevice(hid_device_host, raspberry_pi_port, raspberry_pi_username, hid_device_password,
                                    "sudo python3 hidinput_run_malware.py")
            run_script_on_hiddevice(hid_device_host, raspberry_pi_port, raspberry_pi_username, hid_device_password,
                                    "sudo systemctl start hidinput_running.service")
            # memory dump mit pcileech
            threads_analyze_mem_dump = []
            for i in range(dump_count):
                dump_name = f"/media/lennard/AnalyseDateien/{malware_name}/raw/raw_{i}.bin"
                create_memory_dump(dump_name)

                # Nach dem Erstellen des Dumps die Analyse im Thread starten
                output_dir = f"/media/lennard/AnalyseDateien/{malware_name}/analysed/"
                for plugin in plugins:
                    thread = threading.Thread(target=analyze_memory_dump, args=(dump_name, output_dir, plugin, i))
                    threads_analyze_mem_dump.append(thread)
                    thread.start()

            # raspberry hiddevice runterfahren
            run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username,
                                       ip_traffic_private_key_path,
                                       "sudo systemctl stop limit_kb.service")
            run_script_on_raspberry_pi(ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username,
                                       ip_traffic_private_key_path,
                                       "sudo systemctl stop record_traffic.service")
            run_script_on_hiddevice(hid_device_host, raspberry_pi_port, raspberry_pi_username, hid_device_password,
                                    "sudo shutdown now")

            thread_pcap = threading.Thread(
                target=run_script_on_raspberry_pi,
                args=(
                ip_traffic_pi_host, ip_traffic_pi_port, ip_traffic_pi_username, ip_traffic_private_key_path, "data_get",
                malware_name)
            )
            thread_pcap.start()

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

            # Auf das Ende aller Threads warten
            for thread in threads_analyze_mem_dump:
                thread.join()

            # Put the dumps together and keep the same ones in each file
            for plugin in plugins:
                compare_json_files = []
                for i in range(dump_count):
                    compare_json_files.append(f"{analyse_base_path}{malware_name}{votality_path}{plugin}_{i}.json")

                if plugin == "windows.pslist":
                    merge_unique_pslist_files(compare_json_files,
                                              f"{analyse_base_path}{malware_name}{votality_path}{plugin}_compared.json")

                elif plugin == "windows.pstree":
                    merge_unique_pstree_files(compare_json_files,
                                              f"{analyse_base_path}{malware_name}{votality_path}{plugin}_compared.json")

                elif plugin == "windows.malfind.Malfind":
                    merge_unique_malfind_files(compare_json_files,
                                               f"{analyse_base_path}{malware_name}{votality_path}{plugin}_compared.json")

                elif plugin == "windows.netscan":
                    merge_unique_netscan_files(compare_json_files,
                                               f"{analyse_base_path}{malware_name}{votality_path}{plugin}_compared.json")

                elif plugin == "windows.psscan":
                    merge_unique_psscan_files(compare_json_files,
                                               f"{analyse_base_path}{malware_name}{votality_path}{plugin}_compared.json")

            # Baseline comparison
            for plugin in plugins:
                if plugin == "windows.pslist":
                    filter_unique_pslist_entries(
                        f"{analyse_base_path}{baseline_dir}{votality_path}{plugin}_compared.json",
                        f"{analyse_base_path}{malware_name}{votality_path}{plugin}_compared.json",
                        f"{analyse_base_path}{malware_name}{votality_path}{plugin}_filtered.json")

                elif plugin == "windows.pstree":
                    filter_unique_pstree_entries(
                        f"{analyse_base_path}{baseline_dir}{votality_path}{plugin}_compared.json",
                        f"{analyse_base_path}{malware_name}{votality_path}{plugin}_compared.json",
                        f"{analyse_base_path}{malware_name}{votality_path}{plugin}_filtered.json")

                elif plugin == "windows.malfind.Malfind":
                    filter_unique_malfind_entries(
                        f"{analyse_base_path}{baseline_dir}{votality_path}{plugin}_compared.json",
                        f"{analyse_base_path}{malware_name}{votality_path}{plugin}_compared.json",
                        f"{analyse_base_path}{malware_name}{votality_path}{plugin}_filtered.json")

                elif plugin == "windows.netscan":
                    filter_unique_netscan_entries(
                        f"{analyse_base_path}{baseline_dir}{votality_path}{plugin}_compared.json",
                        f"{analyse_base_path}{malware_name}{votality_path}{plugin}_compared.json",
                        f"{analyse_base_path}{malware_name}{votality_path}{plugin}_filtered.json")

                elif plugin == "windows.psscan":
                    filter_unique_pslist_entries(
                        f"{analyse_base_path}{baseline_dir}{votality_path}{plugin}_compared.json",
                        f"{analyse_base_path}{malware_name}{votality_path}{plugin}_compared.json",
                        f"{analyse_base_path}{malware_name}{votality_path}{plugin}_filtered.json")

            json_files_unfiltered = []
            for plugin in plugins:
                json_files_unfiltered.append(
                    f"{analyse_base_path}{malware_name}{votality_path}{plugin}_compared.json")

            json_files_filtered = []
            for plugin in plugins:
                json_files_filtered.append(
                    f"{analyse_base_path}{malware_name}{votality_path}{plugin}_filtered.json")


            # Check ob Registry fertig ist
            run_script_on_raspberry_pi(raspberry_pi_host, raspberry_pi_port, raspberry_pi_username, private_key_path,
                                       pc_running_info)

            # Switch auf Analyse umschalten
            switch_location = switch_usb(switch_location)
            print(switch_location)
            time.sleep(5)

            differences_registry_json = '/media/lennard/37728ca4-0882-43f0-90ef-cf3374115e25/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/differences_registry_file_hashes.json'
            differences_userdata_json = '/media/lennard/37728ca4-0882-43f0-90ef-cf3374115e25/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/differences_userdata_file_hashes.json'

            data_integrity_path = f'/media/lennard/AnalyseDateien/{malware_name}/data_integrity_report'


            move_file(differences_registry_json, data_integrity_path)
            move_file(differences_userdata_json, data_integrity_path)

            json_files_unfiltered.append(f"{data_integrity_path}/differences_registry_file_hashes.json")
            json_files_unfiltered.append(f"{data_integrity_path}/differences_userdata_file_hashes.json")


            differences_registry_json_filtered = f'{data_integrity_path}/filtered_differences_registry_file_hashes.json'
            differences_userdata_json_filtered = f'{data_integrity_path}/filtered_differences_userdata_file_hashes.json'


            filter_unique_file_entries(f"{analyse_base_path}{baseline_dir}{data_integrity_baseline_path}differences_registry_file_hashes.json"
                                       ,f"{data_integrity_path}/differences_registry_file_hashes.json",differences_registry_json_filtered)

            filter_unique_file_entries(f"{analyse_base_path}{baseline_dir}{data_integrity_baseline_path}differences_userdata_file_hashes.json"
                                       ,f"{data_integrity_path}/differences_userdata_file_hashes.json",differences_userdata_json_filtered)

            json_files_filtered.append(differences_registry_json_filtered)
            json_files_filtered.append(differences_userdata_json_filtered)

            jsons_to_html(json_files_unfiltered, f"{analyse_base_path}{malware_name}/analyzed.html")
            jsons_to_html(json_files_filtered,f"{analyse_base_path}{malware_name}/filtered_analyzed.html")

            thread_pcap.join()
            # Beispielaufruf der Funktion
            pcap_file = f"/media/lennard/AnalyseDateien/{malware_name}/traffic_report/network_traffic.pcap"

            #analyze_pcap(pcap_file, malware_name=malware_name)

        else:
            print(f"Es gibt keine Dateien in {directory}.")
            # Pro Minute ein Check ob neue Datei
            time.sleep(60)

if __name__ == "__main__":
    main()