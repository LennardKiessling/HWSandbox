import serial
import serial.tools.list_ports
import time

def switch_usb(location):
    # Seriellen Port öffnen
    ser = serial.Serial('/dev/ttyUSB0', 9600, timeout=0.1)

    if ser.is_open:
        print("Öffnen erfolgreich")
        print(ser.name)
    else:
        print("Öffnen fehlgeschlagen")

    # Befehle senden
    ser.write(b'AT+CH1=1')  # Relay ON
    time.sleep(1)
    ser.write(b'AT+CH1=0')  # Relay OFF

    # Seriellen Port schließen
    ser.close()
    print("Serieller Port geschlossen")
    if location == "analyse":
        switch_location = "sandbox"
        return switch_location
    else:
        switch_location = "analyse"
        return switch_location