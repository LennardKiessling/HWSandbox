from hidinput_config import *
import random
import time
import math

def random_movement(iterations):
	for i in range(iterations):
    		# Generiere zufällige Zielkoordinaten auf dem Bildschirm
		random_x = random.randint(-100, 100)
		random_y = random.randint(-100, 100)

    		# Bewege die Maus zu den zufälligen Koordinaten
		wind_mouse(0, 0, random_x, random_y)

    		# Optional: Warten zwischen den Bewegungen
		time.sleep(random.randint(0,1))  # z.B. 0.5 Sekunden Pause zwischen Bewegungen

def move_mouse_in_circle(radius, center_x=0, center_y=0, steps=15, iterations=1):
    """
    Bewegt die Maus entlang eines Kreises mit dem angegebenen Mittelpunkt und Radius.

    :param center_x: X-Koordinate des Kreismittelpunkts
    :param center_y: Y-Koordinate des Kreismittelpunkts
    :param radius: Radius des Kreises
    :param steps: Anzahl der Schritte pro Kreis (mehr Schritte = glatterer Kreis)
    :param iterations: Anzahl der kompletten Kreise, die die Maus machen soll
    """
    for iteration in range(iterations):
        for i in range(steps):
            # Berechne den Winkel in Bogenmaß (zwischen 0 und 2*pi für einen vollständigen Kreis)
            angle = 2 * math.pi * (i / steps)

            # Berechne die x- und y-Koordinaten für den aktuellen Punkt auf dem Kreis
            target_x = int(center_x + radius * math.cos(angle))
            target_y = int(center_y - radius * math.sin(angle))  # Minuszeichen für die Y-Achse, um nach oben zu gehen

            # Bewege die Maus zu der berechneten Position auf dem Kreis
            wind_mouse(0, 0, target_x, target_y)

random_movement(2)
move_mouse_in_circle(30)
random_movement(5)
move_mouse_in_circle(60)
type_word("Would you or would you not")
random_movement(10)
move_mouse_in_circle(5, iterations=10)
random_movement(50)
type_word("Hello Dear Keylogger")
