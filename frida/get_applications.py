import os
import sys
import json
import frida
import threading

def get_usb_iphone():
    Type = 'usb'
    if int(frida.__version__.split('.')[0]) < 12:
        Type = 'tether'
    device_manager = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()

    device_manager.on('changed', on_changed)

    device = None
    while device is None:
        devices = [dev for dev in device_manager.enumerate_devices() if dev.type == Type]
        if len(devices) == 0:
            print('Waiting for USB device...')
            changed.wait()
        else:
            device = devices[0]

    device_manager.off('changed', on_changed)

    return device

def get_applications(device):
    try:
        applications = []
        for app in device.enumerate_applications():
            pid = f"{app.pid}" if app.pid != 0 else "-"
            # print(dir(app)) # using dir to get python object all properties
            # small_icon = app.get_small_icon() # _frida.Icon class
            # large_icon = app.get_large_icon() # _frida.Icon class
            applications.append({"pid": pid, "name": app.name, "identifier": app.identifier})
    except Exception as e:
        sys.exit(f"Failed to get applications: {e}")
    return applications


if __name__ == '__main__':
    device = get_usb_iphone()
    applications = get_applications(device)
    # str_app = json.dumps(get_applications(device), ensure_ascii=False, sort_keys=False, indent=2)
    # print(str_app)
    for app in applications:
        print(f'ProcessID: {app["pid"]}\nAppName: {app["name"]}\nBundleID: {app["identifier"]}\n')