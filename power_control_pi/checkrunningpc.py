import time
import gpiod

LED_ON_PIN = 27
chip = gpiod.Chip('gpiochip4')
led_line = chip.get_line(LED_ON_PIN)
led_line.release()
led_line.request(consumer="Transistor", type=gpiod.LINE_REQ_DIR_IN)

try:
   while True:
       pc_state = led_line.get_value()
       time.sleep(5)
       if pc_state == 1:
           print('on')
       else:
           print('off')
finally:
    led_line.release()