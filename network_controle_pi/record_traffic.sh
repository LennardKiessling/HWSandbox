#!/bin/bash

INTERFACE="eth0"

OUTPUT_FILE="/var/log/network_traffic.pcap"

# Dauer der Aufzeichnung (0 = unendlich)
DURATION=0

# FILTER = tcp

# Funktion, um den Netzwerkverkehr aufzuzeichnen
function record_traffic() {
    echo "Starte Aufzeichnung des Netzwerkverkehrs auf $INTERFACE..."
    
    # Überprüfe, ob die Datei bereits existiert und wenn ja entferne sie
    if [ -f "$OUTPUT_FILE" ]; then
        echo "Entferne alte Aufzeichnungsdatei..."
        sudo rm "$OUTPUT_FILE"
    fi

    # Starte tcpdump und zeichne den Verkehr auf
    sudo tcpdump -i $INTERFACE -w $OUTPUT_FILE -G $DURATION "$FILTER"
}

# Aufzeichnung starten
record_traffic
