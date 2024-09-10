import os
import subprocess
import json
import xxhash
import hashlib
import signal

#path to the Windows Registry
registry_path = '/media/lk-switch-linux/Windows/System32/config'
user_path = '/media/lk-switch-linux/Users'


# output file for the hashes
output_file = '/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/registry_file_hashes.json'
user_output_file = '/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/user_file_hashes.json'

# create backup of win10

subprocess.run(["sudo", "partclone.ntfs", "-c", "-d", "-s", "/dev/sda3", "-o", "/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/partclonewin10sda3"], check=True, capture_output=True, text=True)
subprocess.run(["sudo", "dd", "if=/dev/sda", "of=/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/windows10.img", "bs=4M", "status=progress"], check=True, capture_output=True, text=True)
subprocess.run(["sudo", "dd", "if=/dev/sda1", "of=/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/win10sda1", "bs=4M", "status=progress"], check=True, capture_output=True, text=True)
subprocess.run(["sudo", "dd", "if=/dev/sda2", "of=/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/win10sda2", "bs=4M", "status=progress"], check=True, capture_output=True, text=True)
subprocess.run(["sudo", "dd", "if=/dev/sda4", "of=/home/lk-switch-linux/PycharmProjects/RestoreBackup/win10image/win10sda4", "bs=4M", "status=progress"], check=True, capture_output=True, text=True)



def handler(signum, frame):
    raise TimeoutError("Timeout beim Verarbeiten der Datei erreicht.")

# Funktion zum Berechnen des Dateihashs mit Timeout
def calculate_file_hash(file_path, block_size=65536):
    hash_function = xxhash.xxh64()

    # Setze den Signal-Handler und den Alarm für den Timeout
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(1)  # Setzt einen Alarm für 5 Sekunden

    try:
        with open(file_path, "rb") as file:
            block = file.read(block_size)
            while block:
                hash_function.update(block)
                block = file.read(block_size)
        # Deaktiviert den Alarm, wenn der Prozess erfolgreich abgeschlossen wird
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
            if file_hash:
                file_hashes[file] = file_hash

    # Save the hashes to a json file
    save_hashes_to_file(file_hashes, output_file)
    print(f"Hashes saved to {output_file}")

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


mnt_point = "/media/lk-switch-linux"
mnt_device ="/dev/sda3"
# Generate and store hashes
unmount_device(mnt_device)
mount_device(mnt_device,mnt_point)
generate_and_store_hashes(registry_path, output_file)
generate_and_store_hashes(user_path, user_output_file)

unmount_device(mnt_device)
