import sys
import frida

def on_message(message, data):
    print("[on_message] message:", message, "data:", data)

# session = frida.attach(u"微信") # Mac 应用程序
# session = frida.get_usb_device().attach(u'抖音短视频')

device = frida.get_usb_device()
application = device.get_frontmost_application()
if application is None:
  print("please run the application first.")
  sys.exit(-1)
pid = application.pid
session = device.attach(pid)

script = session.create_script("""
rpc.exports.enumerateModules = function () {
  return Process.enumerateModules();
};
""")
script.on("message", on_message)
script.load()

for module in script.exports.enumerate_modules():
    name = module["name"]
    path = module["path"]
    base_addr = module["base"]
    size = module["size"]
    # print(f"type of module: {type(module)}")
    if ".app" in path:
      print(f"image name: {name}\nbase address: {base_addr}\nimage size: {size}\nimage path: {path}\n")