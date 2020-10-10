import frida, sys

f = open('/tmp/objc_msgsend.log', 'w')    

def on_message(msg, _data):
    f.write(msg['payload']+'\n')

frida_script = """
  Interceptor.attach(Module.findExportByName('/usr/lib/libobjc.A.dylib', 'objc_msgSend'), {
    onEnter: function(args) {
        var m = Memory.readCString(args[1]);
        send(m);
    }
  });
"""
device = frida.get_usb_device()
application = device.get_frontmost_application()
if application is None:
    sys.exit(-1)
else:
    pid = application.pid
    session = device.attach(pid)
    script = session.create_script(frida_script)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()