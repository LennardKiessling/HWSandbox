import subprocess
import os
import shutil
import time
import xxhash
import json
import hashlib
import signal

# Befehl für Partclone: sudo partclone.ntfs -c -d -s /dev/sda4 -o /home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/partclonewin10sda4
# Befehl für DD: sudo dd if=/dev/sda of=/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/windows10.img bs=4M status=progress

# Am besten noch eine Funktion einfügen, damit die Dateien die nicht gehashed werden können ins Dokument als nicht lesbar kommen

#path to the Windows Registry
registry_path = "/media/lk-switch-linux/Windows/System32/config"
userdata_path = '/media/lk-switch-linux/Users'


# output file for the hashes
registry_output_file = '/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/after_malware_registry_file_hashes.json'
userdata_output_file = '/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/after_malware_userdata_file_hashes.json'

# Function to calculate the hash of a file
# Signal-Handler für den Timeout
def handler(signum, frame):
    raise TimeoutError("Timeout beim Verarbeiten der Datei erreicht.")

# Funktion zum Berechnen des Dateihashs mit Timeout
def calculate_file_hash(file_path, block_size=65536):
    hash_function = xxhash.xxh64() #should in future be upgraded to xxh3_64

    # Timeout wenn Datei zu lange benötigt
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(3)

    try:
        with open(file_path, "rb") as file:
            block = file.read(block_size)
            while block:
                hash_function.update(block)
                block = file.read(block_size)
        # Deaktiviert den Timeout, da funktioniert
        signal.alarm(0)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    except TimeoutError as e:
        print(f"TimeoutError: {e} - {file_path}")
        return None
    except Exception as e:
        print(f"Error: {e} - {file_path}")
        return None

    return hash_function.hexdigest()


# Function to save the hashes to a JSON file
def save_hashes_to_file(hashes, output_file):
    with open(output_file, 'w') as file:
        json.dump(hashes, file, indent=4)


# Function to calculate and store hashes of registry files
def generate_and_store_hashes(registry_path, output_file):
    file_hashes = {}

    for root, directories, files in os.walk(registry_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_file_hash(file_path)
            #print(file_path)
            if file_hash:
                file_hashes[file] = file_hash

    # Save the hashes to a json file
    save_hashes_to_file(file_hashes, output_file)
    print(f"Hashes saved to {output_file}")

# Funktion um die JSON-Dateien zu laden
def load_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Funktion vergleicht zwei JSON-Dateien
def compare_json(json1, json2):
    differences = {}

    # Überprüfe, welche Schlüssel in json1, aber nicht in json2 sind
    for key in json1:
        if key not in json2:
            differences[key] = {"status": "Missing after MW", "value": json1[key]}
        elif json1[key] != json2[key]:
            differences[key] = {"status": "Changed after MW", "file1_value": json1[key], "file2_value": json2[key]}

    # Überprüfe, welche Schlüssel in json2, aber nicht in json1 sind
    for key in json2:
        if key not in json1:
            differences[key] = {"status": "New after MW", "value": json2[key]}

    return differences

# Funktion um die Unterschiede in eine JSON-Datei zu speichern
def save_differences_to_json(differences, output_file):
    with open(output_file, 'w') as file:
        json.dump(differences, file, indent=4)

# Funktion die eine JSON-Datei löscht
def delete_json_file(file_path):
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"{file_path} wurde erfolgreich gelöscht.")
        else:
            print(f"{file_path} existiert nicht.")
    except Exception as e:
        print(f"Fehler beim Löschen der Datei: {e}")

def rename_file(restoreboot, analyzeboot):
    try:
        if os.path.exists(restoreboot):
            os.rename(restoreboot, analyzeboot)
            print(f"Datei erfolgreich von {restoreboot} nach {analyzeboot} umbenannt.")
        elif os.path.exists(analyzeboot):
            os.rename(analyzeboot, restoreboot)
            print(f"Datei erfolgreich von {analyzeboot} nach {restoreboot} umbenannt.")
    except FileNotFoundError:
        print(f"Die Datei {restoreboot} wurde nicht gefunden.")
    except PermissionError:
        print(f"Keine Berechtigung zum Umbenennen der Datei {restoreboot}.")
    except Exception as e:
        print(f"Ein Fehler ist aufgetreten: {e}")
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

def mount_device(device, mount_point):
    try:
        # Create the mount point directory if it doesn't exist
        subprocess.run(["sudo", "mkdir", "-p", mount_point], check=True)

        # Mount the device
        subprocess.run(["sudo", "mount", device, mount_point], check=True)
        print(f"{device} erfolgreich auf {mount_point} gemountet.")
    except subprocess.CalledProcessError as e:
        print(f"Fehler beim Mounten des Geräts: {e}")

def restore_backup(backup_image_path, target_device):
    try:
        subprocess.run(["ls", target_device], check=True)
        unmount_device(target_device)

        # Wiederherstellen des Images
        restore_command = f"sudo dd if={backup_image_path} | pv | sudo dd of={target_device} bs=4M"
        subprocess.run(restore_command, shell=True, check=True)

        print("Backup erfolgreich wiederhergestellt.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Fehler bei der Wiederherstellung des Backups: {e}")
        try:
            subprocess.run(["ls", "/dev/sda"], check=True)
            unmount_device("/dev/sda")

            # Wiederherstellen des Images
            restore_command = f"sudo dd if=/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/windows10.img | pv | sudo dd of=/dev/sda bs=4M"
            subprocess.run(restore_command, shell=True, check=True)
            return False
        except subprocess.CalledProcessError as e:
            print(f"Fehler bei der Wiederherstellung des alternativen Backups: {e}")


def restore_backup_partclone(backup_image_path, target_device):
    try:
        subprocess.run(["ls", target_device], check=True)
        unmount_device(target_device)

        # Wiederherstellen des Images
        restore_command = f"sudo partclone.ntfs -r -s {backup_image_path} -o {target_device}"
        subprocess.run(restore_command, shell=True, check=True)

        print("Backup erfolgreich wiederhergestellt.")
    except subprocess.CalledProcessError as e:
        print(f"Fehler bei der Wiederherstellung des Backups: {e}")
        try:
            subprocess.run(["ls", "/dev/sda"], check=True)
            unmount_device("/dev/sda")

            # Wiederherstellen des Images
            restore_command = f"sudo dd if=/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/windows10.img | pv | sudo dd of=/dev/sda bs=4M"
            subprocess.run(restore_command, shell=True, check=True)
            return False
        except subprocess.CalledProcessError as e:
            print(f"Fehler bei der Wiederherstellung des alternativen Backups: {e}")


def get_filename(directory):
    try:
        # List all files in the directory
        files = os.listdir(directory)

        # Filter out directories and hidden files (optional)
        files = [f for f in files if os.path.isfile(os.path.join(directory, f)) and not f.startswith('.')]

        # Check if there is exactly one file
        if len(files) == 1:
            return files[0]
    except Exception as e:
        return f"Ein Fehler ist aufgetreten: {e}"

def transfer_file(source_path, destination_path):
    try:
        shutil.move(source_path, destination_path)
        print(f"Datei erfolgreich von {source_path} nach {destination_path} verschoben.")
        os.sync()
    except FileNotFoundError:
        print(f"Die Datei {source_path} wurde nicht gefunden.")
    except PermissionError:
        print(f"Keine Berechtigung zum verschieben der Datei {source_path}.")
    except Exception as e:
        print(f"Ein Fehler ist aufgetreten: {e}")

backup_image_path1 = "/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/win10sda1"
backup_image_path2 = "/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/win10sda2"
backup_image_path3 = "/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/partclonewin10sda3"
backup_image_path4 = "/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/win10sda4"

target_device1 = "/dev/sda1"
target_device2 = "/dev/sda2"
target_device3 = "/dev/sda3"
target_device4 = "/dev/sda4"

restoreboot = "/home/lk-switch-linux/PycharmProjects/RestoreBackup/savestateboot/0.txt"
analyzeboot = "/home/lk-switch-linux/PycharmProjects/RestoreBackup/savestateboot/1.txt"

mnt_point = "/media/lk-switch-linux"

source_path = "/home/lk-switch-linux/PycharmProjects/RestoreBackup/malware"
destination_path = "/media/lk-switch-linux/Users/BA-LK/Documents"

mnt_device = "/dev/sda3"

if __name__ == "__main__":
    if os.path.exists(restoreboot):

        success = restore_backup(backup_image_path1, target_device1)
        if success:
            success = restore_backup(backup_image_path2, target_device2)
        if success:
            success = restore_backup_partclone(backup_image_path3, target_device3)
        if success:
            success = restore_backup(backup_image_path4, target_device4)

        # Übertrage Malware hier
        unmount_device(mnt_device)
        mount_device(mnt_device, mnt_point)
        file = get_filename(source_path)
        transfer_file(f"{source_path}/{file}", destination_path)
        time.sleep(5)
        unmount_device(mnt_device)
        
        rename_file(restoreboot, analyzeboot)
        # Runterfahren
        subprocess.run("sudo shutdown now", shell=True, check=True)

    elif os.path.exists(analyzeboot):
        print("Analyse")
        # Windows Registry auf Veränderungen überprüfen

        # Übertrage Malware hier
        unmount_device(mnt_device)
        mount_device(mnt_device, mnt_point)
        time.sleep(1)

        # Generate and store hashes
        generate_and_store_hashes(registry_path, registry_output_file)
        generate_and_store_hashes(userdata_path, userdata_output_file)

        # Pfade zu den JSON-Dateien
        registry_json_path = '/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/registry_file_hashes.json'
        userdata_json_path = '/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/user_file_hashes.json'

        after_malware_registry_json_path = '/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/after_malware_registry_file_hashes.json'
        after_malware_userdata_json_path = '/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/after_malware_userdata_file_hashes.json'

        differences_registry_file = '/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/differences_registry_file_hashes.json'
        differences_userdata_file = '/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/differences_userdata_file_hashes.json'

        # Lade die JSON-Dateien
        registry_json = load_json(registry_json_path)
        userdata_json = load_json(userdata_json_path)

        after_malware_registry_json = load_json(after_malware_registry_json_path)
        after_malware_userdata_json = load_json(after_malware_userdata_json_path)

        # Vergleiche die JSON-Dateien
        differences_registry = compare_json(registry_json, after_malware_registry_json)
        differences_userfiles = compare_json(userdata_json, after_malware_userdata_json)

        # Debug Ausgabe
        """
        if differences:
            pass
            print("Unterschiede gefunden:")
            for file, diff in differences.items():
                print(f"{file}: {diff}")
        else:
            print("Alle Registry-Dateien sind unverändert.")
        """
        save_differences_to_json(differences_registry, differences_registry_file)
        save_differences_to_json(differences_userfiles, differences_userdata_file)

        delete_json_file(after_malware_userdata_json_path)
        delete_json_file(after_malware_registry_json_path)

        rename_file(restoreboot, analyzeboot)
        # Runterfahren
        unmount_device(mnt_device)
        time.sleep(1)
        subprocess.run("sudo shutdown now", shell=True, check=True)