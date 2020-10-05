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

device = get_usb_iphone()   
pid = device.get_frontmost_application().pid
print(f"proccess id: {pid}")
session = device.attach(pid)
with codecs.open('./appinfo.js', 'r', 'utf-8') as f:
    source = f.read()
script = session.create_script(source)
script.on('message', on_message)
script.load()

deviceinfo: dict = {}
deviceinfo["username"] = script.exports.username();
deviceinfo["fullusername"] = script.exports.fullusername();
deviceinfo["device_name"] = script.exports.devicename();
deviceinfo["system_name"] = script.exports.systemname();
deviceinfo["system_version"] = script.exports.systemversion();
deviceinfo["system_model"] = script.exports.model();
deviceinfo["system_localizemodel"] = script.exports.localizedmodel();
deviceinfo["battery_level"] = script.exports.batterylevel();
deviceinfo["battery_state"] = script.exports.batterystate();
deviceinfo["idfa"] = script.exports.idfa();
deviceinfo["screen_width"] = script.exports.screenwidth();
deviceinfo["screen_height"] = script.exports.screenheight();
deviceinfo["screen_width_in_pixels"] = script.exports.screenwidthinpixels();
deviceinfo["screen_height_in_pixels"] = script.exports.screenheightinpixels();
deviceinfo["scale"] = script.exports.scale();

processInfo: dict = {}
processInfo["host_name"] = script.exports.hostname();
processInfo["process_name"] = script.exports.processname();
processInfo["processid"] = script.exports.processid();
processInfo["osversion"] = script.exports.osversion();


appInfo: dict = {}
appInfo["bundleid"] = script.exports.bundleid();
appInfo["appname"] = script.exports.appname();
appInfo["bundlename"] = script.exports.bundlename();
appInfo["bundle_path"] = script.exports.bundlepath();
appInfo["executable_file"] = script.exports.executablefile();
appInfo["executable_path"] = script.exports.executablepath();
appInfo["receipt_path"] = script.exports.receiptpath();
appInfo["share_frameworks_path"] = script.exports.sharedframeworkspath();
appInfo["private_frameworks_path"] = script.exports.privateframeworkspath();
appInfo["home_directory"] = script.exports.homedir();
appInfo["document_directory"] = script.exports.docdir();
appInfo["temporary_directory"] = script.exports.tempidr();
appInfo["caches_directory"] = script.exports.cachesdir();
appInfo["library_directory"] = script.exports.librarydir();
appInfo["app_version"] = script.exports.appversion();
appInfo["app_short_version"] = script.exports.appshortversion();
appInfo["idfv"] = script.exports.idfv();
appInfo["cookies"] = script.exports.cookies();

info: dict = {}
info["app_info"] = appInfo
info["proccess_info"] = processInfo
info["device_info"] = deviceinfo

strAppInfo = json.dumps(info, ensure_ascii=False, sort_keys=True, indent=2)
print(strAppInfo)

session.detach()