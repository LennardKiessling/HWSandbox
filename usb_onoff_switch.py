import requests
ip_address_usb_switch_Sandbox_TOGGLE = "http://192.168.1.128/cm?cmnd=Power%20TOGGLE"
ip_address_usb_switch_Sandbox_ON = "http://192.168.1.128/cm?cmnd=Power%20ON"
ip_address_usb_switch_Sandbox_OFF = "http://192.168.1.128/cm?cmnd=Power%20off"
def USB_Sandbox_ON(ip_adress_usb_switch):
    try:
        response = requests.get(f"http://{ip_adress_usb_switch}/cm?cmnd=Power%20ON")
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"An error occurred with USB switch: {e}")


def USB_Sandbox_OFF(ip_adress_usb_switch):
    try:
        response = requests.get(f"http://{ip_adress_usb_switch}/cm?cmnd=Power%20TOGGLE")
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"An error occurred with USB switch: {e}")


def USB_Sandbox_Toggle(ip_adress_usb_switch):
    try:
        response = requests.get(f"http://{ip_adress_usb_switch}/cm?cmnd=Power%20off")
        response.raise_for_status()
        if response.status_code == 200:
            return response.text
    except requests.exceptions.RequestException as e:
        print(f"An error occurred with USB switch: {e}")