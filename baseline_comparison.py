import json

def load_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def compare_dicts(baseline_data, malware_data):
    """
    Vergleicht zwei Dictionaries und gibt die Unterschiede zurück.
    """
    differences = {}
    for key in malware_data:
        if key not in baseline_data:
            differences[key] = malware_data[key]
        elif malware_data[key] != baseline_data[key]:
            differences[key] = malware_data[key]
    return differences

def compare_lists(baseline_data, malware_data):
    """
    Vergleicht zwei Listen und gibt die Elemente zurück, die sich unterscheiden.
    """
    differences = [item for item in malware_data if item not in baseline_data]
    return differences

def baseline_comparison(baseline_file, malware_file, output_file):
    baseline_data = load_json(baseline_file)
    malware_data = load_json(malware_file)

    if isinstance(baseline_data, dict) and isinstance(malware_data, dict):
        differences = compare_dicts(baseline_data, malware_data)
    elif isinstance(baseline_data, list) and isinstance(malware_data, list):
        differences = compare_lists(baseline_data, malware_data)
    else:
        raise TypeError("Die Struktur der Baseline und der Malware-Daten stimmt nicht überein.")

    with open(output_file, 'w') as file:
        json.dump(differences, file, indent=4)

    print(f"Die Unterschiede wurden in {output_file} gespeichert.")