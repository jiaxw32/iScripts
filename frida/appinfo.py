import codecs
import frida
import json

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])

session = frida.get_usb_device().attach(u'抖音短视频')
with codecs.open('./appinfo.js', 'r', 'utf-8') as f:
    source = f.read()
script = session.create_script(source)
script.on('message', on_message)
script.load()

deviceinfo: dict = {}
deviceinfo["device_name"] = script.exports.devicename();
deviceinfo["system_name"] = script.exports.systemname();
deviceinfo["system_version"] = script.exports.systemversion();
deviceinfo["system_model"] = script.exports.model();
deviceinfo["system_localizemodel"] = script.exports.localizedmodel();
deviceinfo["idfv"] = script.exports.idfv();
deviceinfo["battery_level"] = script.exports.batterylevel();
deviceinfo["battery_state"] = script.exports.batterystate();

deviceinfo["scale"] = script.exports.scale();

processInfo: dict = {}
processInfo["host_name"] = script.exports.hostname();
processInfo["process_name"] = script.exports.processname();
processInfo["processid"] = script.exports.processid();
processInfo["osversion"] = script.exports.osversion();

# deviceinfo["screen_width"] = script.exports.screenwidth();
# deviceinfo["screen_height"] = script.exports.screenheight();
# deviceinfo["screen_width_in_pixels"] = script.exports.screen_width_in_pixels();
# deviceinfo["screen_height_in_pixels"] = script.exports.screen_height_in_pixels();

appInfo: dict = {}
appInfo["bundleid"] = script.exports.bundleid();
appInfo["appname"] = script.exports.appname();
appInfo["bundlename"] = script.exports.bundlename();
appInfo["executable_file"] = script.exports.executablefile();
appInfo["app_version"] = script.exports.appversion();
appInfo["app_short_version"] = script.exports.appshortversion();

info: dict = {}
info["app_info"] = appInfo
info["proccess_info"] = processInfo
info["device_info"] = deviceinfo

strAppInfo = json.dumps(info, ensure_ascii=False, sort_keys=True, indent=2)
print(strAppInfo)

session.detach()