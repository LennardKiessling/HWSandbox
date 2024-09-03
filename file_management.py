import os
import shutil
import subprocess
import re
import time
import json

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


def sanitize_filename(filename):
    # Entfernt alle nicht erlaubten Zeichen
    sanitized_filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
    # Alles nach dem Punkt abschneiden
    sanitized_filename = sanitized_filename.split('.')[0]
    return sanitized_filename

def check_disk_connected():
    return os.path.exists('/media/lennard/37728ca4-0882-43f0-90ef-cf3374115e25/home/lk-switch-linux/Dokumente/malware')

def create_malware_dir(malware_name):
    # Hauptverzeichnis erstellen
    main_dir = f"/media/lennard/AnalyseDateien/{malware_name}"
    os.mkdir(main_dir, mode=0o777)

    # Unterverzeichnisse erstellen
    subdirs = ['raw', 'analysed', 'data_integrity_report', 'traffic_report']
    for subdir in subdirs:
        os.mkdir(os.path.join(main_dir, subdir), mode=0o777)


def move_file(source,destination):
    try:
        shutil.move(source, destination)
        print(f"Datei wurde nach {destination} (ext. SSD) verschoben.")
        time.sleep(5)
        os.sync()
        unmount_device("/dev/sdc")
    except FileNotFoundError as e:
        print(f"Fehler: Die Datei oder das Verzeichnis wurde nicht gefunden. ({e})")
    except PermissionError as e:
        print(f"Fehler: Berechtigung verweigert. ({e})")
    except Exception as e:
        print(f"Ein unerwarteter Fehler ist aufgetreten: {e}")


def render_entry_as_html(entry, indent=0):
    html = ""
    indent_space = '&nbsp;' * indent * 4  # Adding spaces for indentation in HTML

    html += '<tr>'
    for key, value in entry.items():
        if key != '__children':
            html += f'<td>{indent_space}{value}</td>'
    html += '</tr>'

    if '__children' in entry:
        for child in entry['__children']:
            html += render_entry_as_html(child, indent + 1)

    return html

def jsons_to_html(json_files, html_file):
    with open(html_file, 'w') as f:
        f.write('<html><body>')

        for json_file in json_files:
            f.write(f'<h2>Inhalt von {json_file}</h2>')
            f.write('<table border="1">')

            with open(json_file, 'r') as jf:
                data = json.load(jf)

                if isinstance(data, dict):
                    # Wenn das JSON ein Dictionary ist, wie in Ihrem Fall
                    f.write('<tr><th>File Name</th><th>Status</th><th>File 1 Value</th><th>File 2 Value</th></tr>')

                    for file_name, file_info in data.items():
                        f.write('<tr>')
                        f.write(f'<td>{file_name}</td>')
                        f.write(f'<td>{file_info.get("status", "")}</td>')
                        f.write(f'<td>{file_info.get("file1_value", "")}</td>')
                        f.write(f'<td>{file_info.get("file2_value", "")}</td>')
                        f.write('</tr>')
                else:
                    # Wenn das JSON eine Liste von Dictionaries ist
                    f.write('<tr>')
                    for key in data[0].keys():
                        if key != '__children':
                            f.write(f'<th>{key}</th>')
                    f.write('</tr>')

                    for entry in data:
                        f.write(render_entry_as_html(entry))

            f.write('</table><br>')

        f.write('</body></html>')


def merge_unique_netscan_files(file_list, output_file):
    unique_data = {}

    for file_name in file_list:
        with open(file_name, 'r') as file:
            data = json.load(file)
            for entry in data:
                # Create a unique key for each entry
                unique_key = (
                    entry.get('PID'),
                    entry.get('LocalAddr'),
                    entry.get('LocalPort'),
                    entry.get('Proto'),
                    entry.get('State')
                )
                if unique_key not in unique_data:
                    unique_data[unique_key] = entry

    # Convert the dictionary values back to a list
    merged_data = list(unique_data.values())

    with open(output_file, 'w') as output_file:
        json.dump(merged_data, output_file, indent=4)


def merge_unique_pstree_files(file_list, output_file):
    unique_data = {}
    all_children_pids = set()

    def add_unique_entry(entry):
        unique_key = (
            entry.get('PID'),
            entry.get('PPID'),
            entry.get('ImageFileName'),
            entry.get('CreateTime')
        )
        if unique_key not in unique_data:
            unique_data[unique_key] = entry
            for child in entry.get('__children', []):
                all_children_pids.add(child.get('PID'))
                add_unique_entry(child)

    for file_name in file_list:
        with open(file_name, 'r') as file:
            data = json.load(file)
            for entry in data:
                add_unique_entry(entry)

    # Remove entries that are child processes in another process
    merged_data = [entry for entry in unique_data.values() if entry.get('PID') not in all_children_pids]

    with open(output_file, 'w') as output_file:
        json.dump(merged_data, output_file, indent=4)


def merge_unique_pslist_files(file_list, output_file):
    unique_data = {}

    for file_name in file_list:
        with open(file_name, 'r') as file:
            data = json.load(file)
            for entry in data:
                # Create a unique key for each entry
                unique_key = (
                    entry.get('PID'),
                    entry.get('ImageFileName'),
                    entry.get('CreateTime'),
                    entry.get('Offset(V)')
                )
                if unique_key not in unique_data:
                    unique_data[unique_key] = entry

    # Convert the dictionary values back to a list
    merged_data = list(unique_data.values())

    with open(output_file, 'w') as output_file:
        json.dump(merged_data, output_file, indent=4)

def merge_unique_psscan_files(file_list, output_file):
    unique_data = {}

    for file_name in file_list:
        with open(file_name, 'r') as file:
            data = json.load(file)
            for entry in data:
                unique_key = (
                    entry.get('PID'),
                    entry.get('ImageFileName'),
                    entry.get('CreateTime'),
                    entry.get('Offset(V)')
                )
                if unique_key not in unique_data:
                    unique_data[unique_key] = entry

    merged_data = list(unique_data.values())

    with open(output_file, 'w') as output_file:
        json.dump(merged_data, output_file, indent=4)


def merge_unique_malfind_files(file_list, output_file):
    unique_data = {}

    for file_name in file_list:
        with open(file_name, 'r') as file:
            data = json.load(file)
            for entry in data:
                # Create a unique key for each entry
                unique_key = (
                    entry.get('PID'),
                    entry.get('Start VPN'),
                    entry.get('End VPN'),
                    entry.get('ProcessName')
                )
                if unique_key not in unique_data:
                    unique_data[unique_key] = entry

    # Convert the dictionary values back to a list
    merged_data = list(unique_data.values())

    with open(output_file, 'w') as output_file:
        json.dump(merged_data, output_file, indent=4)