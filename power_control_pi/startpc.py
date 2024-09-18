import gpiod
import time
PIN = 17
chip = gpiod.Chip('gpiochip4')
line = chip.get_line(PIN)
line.request(consumer="TRANSISTOR", type=gpiod.LINE_REQ_DIR_OUT)
try:
       line.set_value(1)
       time.sleep(1) # or 5 when shutoff
       line.set_value(0)
finally:
   line.release()