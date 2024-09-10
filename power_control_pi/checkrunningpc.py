import time
import gpiod

BUTTON_PIN = 27
chip = gpiod.Chip('gpiochip4')
button_line = chip.get_line(BUTTON_PIN)
button_line.release()
button_line.request(consumer="Button", type=gpiod.LINE_REQ_DIR_IN)

try:
   while True:
       button_state = button_line.get_value()
       time.sleep(5)
       if button_state == 1:
           print('on')
       else:
           print('off')
finally:
    button_line.release()