import sys
import codecs
import frida
import json
import threading

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])

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

def attach_application(device, bundleid = None):
    application = device.get_frontmost_application()
    if bundleid is None: 
        if application is not None:
            session = device.attach(application.pid)
            return session
        else:
            print("get active application failed, please run application first.")
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
                print(f"faild to run application {bundleid}. {ex}")
                sys.exit(-1)

def load_script(session, filename):
    with codecs.open(filename, 'r', 'utf-8') as f:
        source = f.read()
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()
    return script

device = get_usb_iphone()
# session = attach_application(device, "com.apple.TestFlight")
session = attach_application(device)
script = load_script(session, "./appinfo.js")

deviceinfo: dict = {}
deviceinfo["username"] = script.exports.username()
deviceinfo["fullusername"] = script.exports.fullusername()
deviceinfo["device_name"] = script.exports.devicename()
deviceinfo["system_name"] = script.exports.systemname()
deviceinfo["system_version"] = script.exports.systemversion()
deviceinfo["system_model"] = script.exports.model()
deviceinfo["system_localizemodel"] = script.exports.localizedmodel()
deviceinfo["battery_level"] = script.exports.batterylevel()
deviceinfo["battery_state"] = script.exports.batterystate()
deviceinfo["idfa"] = script.exports.idfa()
deviceinfo["screen_info"] = script.exports.screeninfo()
deviceinfo["jailbroken"] = script.exports.isjailbroken()
deviceinfo["hw.model"] = script.exports.sysctlstringbyname("hw.model")
deviceinfo["hw.machine"] = script.exports.sysctlstringbyname("hw.machine")
deviceinfo["kern.version"] = script.exports.sysctlstringbyname("kern.version")
deviceinfo["kern.osversion"] = script.exports.sysctlstringbyname("kern.osversion")
deviceinfo["hw.cputype"] = script.exports.sysctlInt32ValueByName("hw.cputype")
deviceinfo["hw.cpusubtype"] = script.exports.sysctlInt32ValueByName("hw.cpusubtype")
deviceinfo["hw.memsize"] = script.exports.sysctluint64valuebyname("hw.memsize")
deviceinfo["storage_size"] = script.exports.storagesize()
deviceinfo["free_size"] = script.exports.freesize()
carrierInfo = script.exports.carrierinfo() # <class 'dict'>
deviceinfo["carrier_info"] = carrierInfo

appInfo: dict = {}
appInfo["bundleid"] = script.exports.bundleid()
appInfo["appname"] = script.exports.mainBundleInfoForKey("CFBundleDisplayName")
appInfo["bundlename"] = script.exports.mainBundleInfoForKey("CFBundleName")
appInfo["app_version"] = script.exports.mainBundleInfoForKey("CFBundleVersion")
appInfo["app_short_version"] = script.exports.mainBundleInfoForKey("CFBundleShortVersionString")
appInfo["idfv"] = script.exports.idfv()
appInfo["cookies"] = script.exports.cookies()
appInfo["app_module"] = script.exports.moduleinfo()
appInfo["app_path"] = script.exports.apppathinfo()

processInfo = script.exports.processinfo()

info: dict = {}
info["app_info"] = appInfo
info["proccess_info"] = processInfo
info["device_info"] = deviceinfo

strAppInfo = json.dumps(info, ensure_ascii=False, sort_keys=True, indent=2)
print(strAppInfo)

session.detach()