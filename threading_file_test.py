import os
import time
from concurrent.futures import ThreadPoolExecutor

# Verzeichnis, das durchsucht werden soll
directory = r"C:\Windows\System32"

# Funktion, um den Inhalt einer Datei zu lesen
def read_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            # Datei komplett einlesen und den Inhalt zurückgeben
            content = file.read()
        return file_path, content
    except (PermissionError, FileNotFoundError):
        return file_path, None

# Funktion, um alle Dateien im Verzeichnis zu finden
def get_all_files(directory):
    file_paths = []
    for root, dirs, files in os.walk(directory):
        for file_name in files:
            file_paths.append(os.path.join(root, file_name))
    return file_paths

# Single-threaded Einlesen
def single_threaded_read(all_files):
    file_contents = []
    for file_path in all_files:
        file_contents.append(read_file(file_path))
    return file_contents

# Multi-threaded Einlesen
def multi_threaded_read(all_files, num_threads):
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        file_contents = list(executor.map(read_file, all_files))
    return file_contents

# Hauptprogramm
if __name__ == "__main__":
    all_files = get_all_files(directory)
    print(len(all_files))

    start_time = time.time()
    threads_used = 4
    file_contents_multi = multi_threaded_read(all_files, num_threads=threads_used)

    end_time = time.time()
    elapsed_time_multi = end_time - start_time
    print(f"Das Einlesen aller Dateien im Multi-Threading dauerte {elapsed_time_multi:.6f} Sekunden.\n")

    start_time = time.time()

    file_contents_single = single_threaded_read(all_files)

    end_time = time.time()
    elapsed_time_single = end_time - start_time
    print(f"Das Einlesen aller Dateien im Single-Threading dauerte {elapsed_time_single:.6f} Sekunden.\n")



    # Ergebnisse vergleichen
    print(f"Vergleich:\nSingle-Threading: {elapsed_time_single:.6f} Sekunden\nMulti-Threading ({threads_used} Threads): {elapsed_time_multi:.6f} Sekunden")
