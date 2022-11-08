var NSBundle = ObjC.classes.NSBundle;
var path = NSBundle.mainBundle().bundlePath().toString();
console.log("bundle path: " + path);

var addr = Module.findExportByName("libSystem.B.dylib", "_dyld_get_image_vmaddr_slide");
var _dyld_get_image_vmaddr_slide = new NativeFunction(addr, "long", ["uint"]);

const pattern = '01 10 00 D4'; // svc 0x80

Process.enumerateModulesSync().forEach((module, index) => {
  var slide = _dyld_get_image_vmaddr_slide(index);
  // var startAddr = module.base;
  // var endAddr = startAddr.add(module.size);
  // console.log("Module name: " + module.name + ", size: " + module.size);
  // console.log('base address: ' + startAddr + ', end address: ' + endAddr + ", slide: 0x" + slide.toString(16));

  if (module.path.indexOf(path) != -1) {
    console.log(module.path);
    Memory.scan(module.base, module.size, pattern, {
      onMatch(address, size) {
        const offset = address.sub(slide);
        console.log('module: ' + module.name + ', found svc instruction at ' + address + ", offset: " + offset);
        console.log(hexdump(address.sub(0x20), {length: 48, ansi: false, header: false }), "\n");
      },
      onComplete() {
        console.log('Memory.scan() complete');
      }
    });
  }
});