import os
import shutil
import subprocess
import re
import time


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
    main_dir = f"/media/lennard/Analyse Dateien/{malware_name}"
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
