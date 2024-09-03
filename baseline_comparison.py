import json


def is_safe_ip(ip):
    safe_ips = {
        "192.168.1.1",
        "192.168.1.2",
        "192.168.2.132",
        "127.0.0.1",
        "8.8.8.8",
        "0.0.0.0",
        "::"
        "10.0.0.1",
    }
    return ip in safe_ips


# Funktion zur Überprüfung auf verdächtige Ports
def is_suspicious_port(port):
    suspicious_ports = {21, 23, 25, 80, 110, 113, 135, 137, 139, 143, 443, 465, 513, 514, 1080, 1524,
                        2000, 2049, 2121, 3306, 4000, 4444, 5432, 6666, 6667, 10008, 12345, 27374, 31337,
                        }
    return port in suspicious_ports


# Funktion zur Überprüfung auf verdächtige Verbindungszustände
def is_suspicious_state(state):
    suspicious_states = {"SYN_SENT", "TIME_WAIT", "CLOSE_WAIT"}
    return state in suspicious_states


def filter_unique_netscan_entries(baseline_file, new_file, output_file):
    # Load the baseline data
    with open(baseline_file, 'r') as baseline_f:
        baseline_data = json.load(baseline_f)

    # Load the new data
    with open(new_file, 'r') as new_f:
        new_data = json.load(new_f)

    # Function to extract a unique key for each entry in netscan
    def extract_key(entry):
        return (
            entry.get('Owner'),
            entry.get('LocalAddr'),
            entry.get('LocalPort'),
            entry.get('Proto'),
            entry.get('State'),
            entry.get('ForeignAddr'),
            entry.get('ForeignPort')
        )

    # Create a set of unique keys from the baseline data
    baseline_keys = set(
        extract_key(entry) for entry in baseline_data
    )

    # Filter the new data to find entries that are not in the baseline
    filtered_data = []

    def is_dangerous(entry):
        return (
                not is_safe_ip(entry.get('ForeignAddr')) or  # Prüfe, ob die IP nicht in der Whitelist ist
                is_suspicious_port(entry.get('LocalPort')) or
                is_suspicious_state(entry.get('State'))
        )

    for entry in new_data:
        current_key = extract_key(entry)
        is_new = current_key not in baseline_keys

        if is_new:
            if is_dangerous(entry):
                entry["Dangerous"] = True
            filtered_data.append(entry)

    # Write the filtered data to the output file
    with open(output_file, 'w') as output_f:
        json.dump(filtered_data, output_f, indent=4)


def is_legitimate_process(process_name, process_path):
    legitimate_processes = {
        "system": "C:\\Windows\\System32\\",
        "smss.exe": "C:\\Windows\\System32\\",
        "csrss.exe": "C:\\Windows\\System32\\",
        "wininit.exe": "C:\\Windows\\System32\\",
        "services.exe": "C:\\Windows\\System32\\",
        "lsass.exe": "C:\\Windows\\System32\\",
        "svchost.exe": "C:\\Windows\\System32\\",
        "winlogon.exe": "C:\\Windows\\System32\\",
        "explorer.exe": "C:\\Windows\\",
        "taskmgr.exe": "C:\\Windows\\System32\\",
        "spoolsv.exe": "C:\\Windows\\System32\\",
        "msmpeng.exe": "C:\\Program Files\\Windows Defender\\",
        "wuauclt.exe": "C:\\Windows\\System32\\",
        "trustedinstaller.exe": "C:\\Windows\\servicing\\",
        "notepad.exe": "C:\\Windows\\System32\\",
        "cmd.exe": "C:\\Windows\\System32\\",
        "powershell.exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\",
        "rundll32.exe": "C:\\Windows\\System32\\",
        "mshta.exe": "C:\\Windows\\System32\\",
        "wscript.exe": "C:\\Windows\\System32\\",
        "cscript.exe": "C:\\Windows\\System32\\"
    }

    # Liste von Prozessen, die häufig für bösartige Zwecke missbraucht werden
    suspicious_processes = [
        "svchost.exe",
        "powershell.exe",
        "cmd.exe",
        "rundll32.exe",
        "mshta.exe",
        "wscript.exe",
        "cscript.exe"
    ]

    expected_path = legitimate_processes.get(process_name.lower())

    if process_path is None:
        return False  # Kein Prozesspfad vorhanden, daher als nicht legitim betrachten

    if process_name.lower() in suspicious_processes:
        # Zusätzliche Überprüfung für verdächtige Prozesse
        if not process_path.lower().startswith(expected_path.lower()):
            return False  # Markiere als potenziell gefährlich
        else:
            return True  # Legitimer Prozess im erwarteten Pfad
    else:
        # Normale Überprüfung für andere Prozesse
        return expected_path and process_path.lower().startswith(expected_path.lower())


def filter_unique_pstree_entries(baseline_file, new_file, output_file):
    # Load the baseline data
    with open(baseline_file, 'r') as baseline_f:
        baseline_data = json.load(baseline_f)

    # Load the new data
    with open(new_file, 'r') as new_f:
        new_data = json.load(new_f)

    # Function to extract a unique key for each process
    def extract_key(entry):
        return (
            entry.get('ImageFileName'),
            entry.get('Path'),
            entry.get('Cmd'),
            entry.get('Wow64')
        )

    # Create a set of unique keys from the baseline data
    def collect_keys(data):
        keys = set()
        stack = data[:]
        while stack:
            current = stack.pop()
            keys.add(extract_key(current))
            stack.extend(current.get('__children', []))
        return keys

    baseline_keys = collect_keys(baseline_data)

    # Filter the new data to find entries that are not in the baseline
    filtered_data = []

    def filter_entries(data, parent_is_new=False):
        for entry in data:
            current_key = extract_key(entry)
            is_new = current_key not in baseline_keys

            # Check if the process is legitimate
            is_legit = is_legitimate_process(entry.get('ImageFileName'), entry.get('Path'))

            # If the process is new or its parent is new, and it's not legitimate, mark it as dangerous
            if is_new or parent_is_new:
                if not is_legit:
                    entry["Dangerous"] = True
                filtered_data.append(entry)

            filter_entries(entry.get('__children', []), is_new)

    filter_entries(new_data)

    # Write the filtered data to the output file
    with open(output_file, 'w') as output_f:
        json.dump(filtered_data, output_f, indent=4)


suspicious_hex_patterns = ["cc", "e9", "ff e0", "48 8b", "4d 5a"]

def is_suspicious_hex_disasm(disasm):
    # Flatten the disasm string by removing spaces and quotes
    flattened_disasm = disasm.replace("\"", "").replace(" ", "").lower()
    # Check if any suspicious pattern is present in the disasm string
    return any(pattern.replace(" ", "").lower() in flattened_disasm for pattern in suspicious_hex_patterns)

def filter_unique_malfind_entries(baseline_file, new_file, output_file):
    # Load the baseline data
    with open(baseline_file, 'r') as baseline_f:
        baseline_data = json.load(baseline_f)

    # Load the new data
    with open(new_file, 'r') as new_f:
        new_data = json.load(new_f)

    # Function to extract a unique key for each entry in malfind
    def extract_key(entry):
        return (
            entry.get('Process'),
            entry.get('Disasm'),
            entry.get('Protection')
        )

    # Create a set of unique keys from the baseline data
    baseline_keys = set(
        extract_key(entry) for entry in baseline_data
    )

    # Filter the new data to find entries that are not in the baseline
    filtered_data = []
    for entry in new_data:
        if extract_key(entry) not in baseline_keys:
            # Check if the entry is suspicious based on the hexadecimal disasm
            is_dangerous = is_suspicious_hex_disasm(entry.get('Disasm'))
            if is_dangerous:
                entry["Dangerous"] = True
            filtered_data.append(entry)

    # Write the filtered data to the output file
    with open(output_file, 'w') as output_f:
        json.dump(filtered_data, output_f, indent=4)


def filter_unique_pslist_entries(baseline_file, new_file, output_file):
    # Load the baseline data
    with open(baseline_file, 'r') as baseline_f:
        baseline_data = json.load(baseline_f)

    # Load the new data
    with open(new_file, 'r') as new_f:
        new_data = json.load(new_f)

    # Function to extract a unique key for each entry in pslist
    def extract_key(entry):
        return (
            entry.get('ImageFileName'),
            entry.get('Wow64'),
            entry.get('SessionId')
        )

    # Create a set of unique keys from the baseline data
    baseline_keys = set(
        extract_key(entry) for entry in baseline_data
    )

    # Filter the new data to find entries that are not in the baseline
    filtered_data = [
        entry for entry in new_data
        if extract_key(entry) not in baseline_keys
    ]

    # Write the filtered data to the output file
    with open(output_file, 'w') as output_f:
        json.dump(filtered_data, output_f, indent=4)

def filter_unique_file_entries(baseline_file, new_file, output_file):
    # Laden der Baseline-Daten
    with open(baseline_file, 'r') as baseline_f:
        baseline_data = json.load(baseline_f)

    # Laden der neuen Daten
    with open(new_file, 'r') as new_f:
        new_data = json.load(new_f)

    # Funktion zur Erstellung eines eindeutigen Schlüssels für jeden Eintrag
    def extract_key(file_name, file_info):
        return (
            file_name,
            file_info.get('status')
        )

    # Erstellen eines Sets von eindeutigen Schlüsseln aus den Baseline-Daten
    baseline_keys = set(
        extract_key(file_name, file_info) for file_name, file_info in baseline_data.items()
    )

    # Filtern der neuen Daten, um Einträge zu finden, die nicht in der Baseline vorhanden sind
    filtered_data = {
        file_name: file_info for file_name, file_info in new_data.items()
        if extract_key(file_name, file_info) not in baseline_keys
    }

    # Schreiben der gefilterten Daten in die Ausgabedatei
    with open(output_file, 'w') as output_f:
        json.dump(filtered_data, output_f, indent=4)