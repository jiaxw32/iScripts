
function getPt(addr) {
  if (typeof addr == "number") {
      addr = ptr(addr);
  }
  return Memory.readPointer(addr);
}

function getStr(addr) {
  if (typeof addr == "number") {
      addr = ptr(addr);
  }
  return Memory.readUtf8String(addr);
}

var address = Module.getExportByName(null, 'dladdr');
var dladdr = new NativeFunction(address, 'int', ["pointer", "pointer"])

function findImagePathOfSymbol(addr) {
  if (typeof addr == 'number') {
    addr = ptr(addr);
  }

  var dl_info = Memory.alloc(Process.pointerSize * 4); 

  // dladdr() returns 0 on error, and nonzero on success.
  var ret = dladdr(addr, dl_info); 
  if (ret != 0) {
    var dli_fbase = getPt(dl_info.add(Process.pointerSize));
    console.log("image base address: " + dli_fbase.toString());

    var dli_fname = getPt(dl_info);
    console.log("image file name: " + getStr(dli_fname));

    // var dli_sname = getPt(dl_info.add(Process.pointerSize * 2));
    // var sname = getStr(dli_sname);
    // console.log("sname: " + sname);

    // var dli_saddr = getPt(dl_info.add(Process.pointerSize * 3));
    // console.log("saddr: " + dli_saddr);
  } else {
    console.log('call dladdr failed, please check your input params.');
  }
}

if (ObjC.available) {
  if ("UIViewController" in ObjC.classes) {
    var viewDidLoad1 = ObjC.classes.UIViewController["- viewDidLoad"];
    console.log("-[UIViewController viewDidLoad] imp:", ptr(viewDidLoad1.implementation));
    findImagePathOfSymbol(viewDidLoad1.implementation);
    // var module = Process.findModuleByAddress(viewDidLoad1.implementation);
    // console.log(module.base, module.name, module.path);
  }

  if ("STStorageAppDetailController" in ObjC.classes) {
    var STStorageAppDetailController = ObjC.classes.STStorageAppDetailController
    console.log("STStorageAppDetailController class:", ptr(STStorageAppDetailController));
    findImagePathOfSymbol(STStorageAppDetailController); 

    var module = Process.findModuleByAddress(ptr(STStorageAppDetailController));
    if (module != null) {
      console.log(module.base, module.name, module.path);
    } else {
      console.log('Process.findModuleByAddress() failed.');
    }
  }
}