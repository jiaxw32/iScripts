import sys
import codecs
import frida
import json
import threading
import argparse

# TODO: 1. keychain 2. signature 3. imei 4. 参考利落检测器，获取更多设备信息

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])

def get_usb_iphone():
    device_type = 'usb'
    if int(frida.__version__.split('.')[0]) < 12:
        device_type = 'tether'
    device_manager = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()

    device_manager.on('changed', on_changed)

    device = None
    while device is None:
        devices = [dev for dev in device_manager.enumerate_devices() if dev.type == device_type]
        if len(devices) == 0:
            print('Waiting for USB device...')
            changed.wait()
        else:
            device = devices[0]

    device_manager.off('changed', on_changed)

    return device

def attach_application(device, bundleid = None):
    application = device.get_frontmost_application()
    if bundleid is None: 
        if application is not None:
            session = device.attach(application.pid)
            return session
        else:
            print("No frontmost application on iPhone, please run an application first.")
            sys.exit(-1)
    else:
        if application is not None and application.identifier == bundleid:
            session = device.attach(application.pid)
            return session
        else:
            try:
                pid = device.spawn([bundleid])
                session = device.attach(pid)
                device.resume(pid)
                return session
            except Exception as identifier:
                print(f"faild to run the application {bundleid}. {ex}")
                sys.exit(-1)

def load_script(session, filename):
    with codecs.open(filename, 'r', 'utf-8') as f:
        source = f.read()
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()
    return script

def get_all_appinfo():
    """
    docstring
    """
    appinfo: dict = {}
    appinfo["base"] = script.exports.appbaseinfo()
    appinfo["cookies"] = script.exports.cookies()
    appinfo["module"] = script.exports.moduleinfo()
    appinfo["path"] = script.exports.apppathinfo()
    return appinfo

def print_appinfo(info):
    """
    docstring
    """
    appinfo = json.dumps(info, ensure_ascii=False, sort_keys=True, indent=2)
    print(appinfo)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Welcome frida appinfo.')
    parser.add_argument('-a', '--all', dest='get_all_appinfo', action='store_true', help='Get all app info.')
    parser.add_argument('-b', '--basic', dest='get_app_basicinfo', action='store_true', help='Get App basic information.')
    parser.add_argument('-c', '--cookie', dest='get_app_cookie', action='store_true', help='Get App cookies.')
    parser.add_argument('-d', '--device', dest='get_device_info', action='store_true', help='Get Device information.')
    parser.add_argument('-m0', '--Module', dest='get_app_all_module', action='store_true', help='Get App all module info, include all linked dynamic libiray.')
    parser.add_argument('-m1', '--module', dest='get_app_module', action='store_true', help='Get App module info.')
    parser.add_argument('-m2', '--msmodule', dest='get_app_ms_module', action='store_true', help='Get App module info.')
    parser.add_argument('-p', '--path', dest='get_app_path', action='store_true', help='Get App path.')
    parser.add_argument('-P', '--Process', dest='get_app_process_info', action='store_true', help='Get App Process Info.')
    args = parser.parse_args()
    # parser.print_help()

    device = get_usb_iphone()
    # attach current active application
    session = attach_application(device)
    # attach application by app identifier.
    # session = attach_application(device, "com.apple.TestFlight") 
    script = load_script(session, "./appinfo.js")

    info: dict = {}

    appinfo: dict = {}
    # appinfo["allbundle"] = script.exports.allbundleinfo(0)

    if args.get_app_basicinfo:
        appinfo["base"] = script.exports.appbaseinfo()
    if args.get_app_cookie:
        appinfo["cookies"] = script.exports.cookies()
    if args.get_app_all_module:
        appinfo["module"] = script.exports.moduleinfo(0)
    if args.get_app_module and not args.get_app_all_module:
        appinfo["module"] = script.exports.moduleinfo(1)
    if args.get_app_ms_module and not args.get_app_all_module:
        appinfo["module"] = script.exports.moduleinfo(2)
    if args.get_app_path:
        appinfo["path"] = script.exports.apppathinfo()
    if args.get_app_process_info:
        info["proccess_info"] = script.exports.processinfo()
    if args.get_device_info:
        info["device_info"] = script.exports.deviceinfo()

    if args.get_all_appinfo or len(sys.argv[1:]) == 0:
        appinfo = get_all_appinfo()
        info["proccess_info"] = script.exports.processinfo()

    if len(appinfo):
        info["app_info"] = appinfo

    print_appinfo(info)
    session.detach()