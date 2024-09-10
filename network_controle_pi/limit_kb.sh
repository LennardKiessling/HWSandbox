#!/bin/bash

# Interface, das überwacht werden soll (anpassen je nach Bedarf)
INTERFACE="eth0"

# Zeitintervall in Sekunden für die Aktualisierung des Counters
INTERVAL=1

# Schwellenwert für übertragene Bytes
BYTE_THRESHOLD=51200000

# 1. Löschen aller iptables-Regeln
echo "Lösche alle iptables-Regeln..."
sudo iptables -F
sudo iptables -X
sudo iptables -Z
echo "Alle iptables-Regeln wurden gelöscht."

# Funktion, um die Anzahl der gesendeten Bytes zu extrahieren
function get_bytes() {
    cat /sys/class/net/$INTERFACE/statistics/tx_bytes
}

# Startwert des Counters
initial_bytes=$(get_bytes)

# 2. Hauptschleife zur kontinuierlichen Ausgabe des Counters
while true; do
    # Aktueller Wert der übertragenen Bytes
    current_bytes=$(get_bytes)

    # Berechne die Differenz der Bytes seit Start
    bytes_diff=$((current_bytes - initial_bytes))

    # Ausgabe der übertragenen Bytes
    echo "Übertragene Bytes: $bytes_diff"

    # Überprüfe, ob der Schwellenwert erreicht wurde
    if [ "$bytes_diff" -ge "$BYTE_THRESHOLD" ]; then
        # Akzeptiere nur noch DNS Anfragen

        #sudo iptables -A FORWARD -i eth0 -o wlan0 -p tcp --dport 53 -j ACCEPT
        #sudo iptables -A FORWARD -i eth0 -o wlan0 -p udp --dport 53 -j ACCEPT
        #sudo iptables -A FORWARD -i eth0 -o wlan0 -j DROP

        break
    fi

    sleep $INTERVAL
done
