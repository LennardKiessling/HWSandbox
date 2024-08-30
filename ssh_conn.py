import paramiko

def run_script_on_hiddevice(host, port, username, password, command):
    # Erstelle ein SSH-Client-Objekt
    client = paramiko.SSHClient()
    # Automatisch unbekannte Schlüssel akzeptieren
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Verbinde mit dem HID-Gerät
        client.connect(hostname=host, port=port, username=username, password=password, pkey=None)
        print("Verbindung hergestellt")

        # Führe den Befehl aus
        stdin, stdout, stderr = client.exec_command(command, get_pty=True)
        print("Befehl wird ausgeführt...")

        # Lese die Ausgabe Zeile für Zeile
        while True:
            line = stdout.readline()
            if not line:
                break
            print(line, end='')  # Ausgabe der Zeile auf der Konsole

    except Exception as e:
        print(f"Verbindung fehlgeschlagen: {e}")

    finally:
        # Schließen der SSH-Verbindung
        print("Verbindung geschlossen")
        client.close()


def run_script_on_raspberry_pi(host, port, username, private_key_path, script_path, ip_traffic_pi_host="192.168.1.230",malware_name=None,pc_running_info="/home/lennard/PycharmProjects/raspberrypi/checkrunningpc.py" ):
    # Erstelle ein SSH-Client-Objekt
    client = paramiko.SSHClient()
    # Automatisch unbekannte Schlüssel akzeptieren
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Laden des Private Keys
    private_key = paramiko.RSAKey(filename=private_key_path)

    try:

        # Verbinde mit dem Raspberry Pi
        client.connect(hostname=host, port=port, username=username, pkey=private_key)
        print("Verbindung hergestellt")

        if host == ip_traffic_pi_host:
            if script_path == "data_get":
                # SFTP-Sitzung starten
                sftp = client.open_sftp()

                remote_traffic_report_path = "/var/log/network_traffic.pcap"
                local_traffic_path_path = (f"/media/lennard/AnalyseDateien/{malware_name}/traffic_report/network_traffic.pcap")

                # Traffic von Pi runterladen
                sftp.get(remote_traffic_report_path, local_traffic_path_path)
                print(f"Die Datei wurde erfolgreich heruntergeladen nach {local_traffic_path_path}")

                # SFTP-Sitzung schließen
                sftp.close()
            else:
                client.exec_command(script_path)
                print("Script wird ausgeführt...")
        else:
            # Wenn das Script spezifisch ist
            if script_path == pc_running_info:
                # Führe das Script aus
                stdin, stdout, stderr = client.exec_command(f'python3 {script_path}', get_pty=True)
                print("Script wird ausgeführt...")
                # Lese die Ausgabe Zeile für Zeile
                while True:
                    # Lese eine Zeile der Standardausgabe
                    line = stdout.readline()
                    if not line:
                        print("not line")
                        break
                    print(line, end='')  # Ausgabe der Zeile auf der Konsole
                    # Überprüfe, ob die Zeile "off" enthält
                    if "off" in line:
                        print("Das Script hat 'off' zurückgegeben. Beende die Schleife.")
                        break
            else:
                client.exec_command(f'python3 {script_path}')
                print("Script wird ausgeführt...")


    except Exception as e:
        print(f"Verbindung fehlgeschlagen: {e}")

    finally:
        # Schließen der SSH-Verbindung
        print("Verbindung geschlossen")
        client.close()