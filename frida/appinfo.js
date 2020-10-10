Module.ensureInitialized("UIKit");

function exportFunction(type, name, ret, args) {
  var nptr;
  nptr = Module.findExportByName(null, name);
  if (nptr === null) {
    console.log("cannot find " + name);
    return null;
  } else {
    if (type === "f") {
      var funclet = new NativeFunction(nptr, ret, args);
      if (typeof funclet === "undefined") {
        console.log("parse error " + name);
        return null;
      }
      return funclet;
    } else if (type === "d") {
      var datalet = Memory.readPointer(nptr);
      if (typeof datalet === "undefined") {
        console.log("parse error " + name);
        return null;
      }
      return datalet;
    }
  }
}

var sysctlbyname = exportFunction("f", "sysctlbyname", "int", [
  "pointer",
  "pointer",
  "pointer",
  "pointer",
  "uint",
]);

var NSSearchPathForDirectoriesInDomains = exportFunction(
  "f",
  "NSSearchPathForDirectoriesInDomains",
  "pointer",
  ["int", "int", "int"]
);
var NSHomeDirectory = exportFunction("f", "NSHomeDirectory", "pointer", []);
var NSTemporaryDirectory = exportFunction(
  "f",
  "NSTemporaryDirectory",
  "pointer",
  []
);
var NSUserName = exportFunction("f", "NSUserName", "pointer", []);
var NSFullUserName = exportFunction("f", "NSFullUserName", "pointer", []);

function userName() {
  var dir = NSUserName();
  return ObjC.Object(dir).toString();
}

function fullUserName() {
  var dir = NSFullUserName();
  return ObjC.Object(dir).toString();
}

function documentDirectory() {
  var NSDocumentDirectory = 9;
  var NSUserDomainMask = 1;
  var npdirs = NSSearchPathForDirectoriesInDomains(
    NSDocumentDirectory,
    NSUserDomainMask,
    1
  );
  return ObjC.Object(npdirs).objectAtIndex_(0).toString();
}

function libraryDirectory() {
  var NSLibraryDirectory = 5;
  var NSUserDomainMask = 1;
  var npdirs = NSSearchPathForDirectoriesInDomains(
    NSLibraryDirectory,
    NSUserDomainMask,
    1
  );
  return ObjC.Object(npdirs).objectAtIndex_(0).toString();
}

function cachesDirectory() {
  var NSCachesDirectory = 13;
  var NSUserDomainMask = 1;
  var npdirs = NSSearchPathForDirectoriesInDomains(
    NSCachesDirectory,
    NSUserDomainMask,
    1
  );
  return ObjC.Object(npdirs).objectAtIndex_(0).toString();
}

function homeDirectory() {
  var dir = NSHomeDirectory();
  return ObjC.Object(dir).toString();
}

function temporaryDirectory() {
  var dir = NSTemporaryDirectory();
  return ObjC.Object(dir).toString();
}

function storageSize() {
  var homepath = NSHomeDirectory();
  var attr = defaultFileManager.attributesOfFileSystemForPath_error_(
    homepath,
    NULL
  );
  return attr.objectForKey_("NSFileSystemSize").unsignedLongLongValue();
}

function freeSize() {
  var homepath = NSHomeDirectory();
  var attr = defaultFileManager.attributesOfFileSystemForPath_error_(
    homepath,
    NULL
  );
  return attr.objectForKey_("NSFileSystemFreeSize").unsignedLongLongValue();
}

var UIDevice = ObjC.classes.UIDevice;
var currentDevice = UIDevice.currentDevice();

var UIScreen = ObjC.classes.UIScreen;
var mainScreen = UIScreen.mainScreen();

var NSBundle = ObjC.classes.NSBundle;
var mainBundle = NSBundle.mainBundle();

var NSFileManager = ObjC.classes.NSFileManager;
var defaultFileManager = NSFileManager.defaultManager();

function mainBundleInfoForKey(key) {
  return mainBundle.infoDictionary().objectForKey_(key).toString();
}

function deviceName() {
  return currentDevice.name().toString();
}

function systemName() {
  return currentDevice.systemName().toString();
}

function systemVersion() {
  return currentDevice.systemVersion().toString();
}

function deviceModel() {
  return currentDevice.model().toString();
}

function localizedModel() {
  return currentDevice.localizedModel().toString();
}

function identifierForVendor() {
  return currentDevice.identifierForVendor().UUIDString().toString();
}

function advertisingIdentifier() {
  if (ObjC.available && "ASIdentifierManager" in ObjC.classes) {
    var ASIdentifierManager = ObjC.classes.ASIdentifierManager;
    return ASIdentifierManager.sharedManager()
      .advertisingIdentifier()
      .UUIDString()
      .toString();
  } else {
    send({message: "current app doesn't support AdSupport module."});
    return "";
  }
}


function batteryLevel() {
  // Battery level ranges from 0.0 (fully discharged) to 1.0 (100% charged). Before accessing this property, ensure that battery monitoring is enabled.
  // If battery monitoring is not enabled, the value of this property is –1.0.
  return currentDevice.batteryLevel();
}

function batteryState() {
  var state = currentDevice.batteryState().toNumber();
  // console.log("battery state: " + state + typeof state);
  var ret = "unknown";
  switch (state) {
    case 0:
      ret = "unknown";
      break;
    case 1:
      ret = "unplugged";
      break;
    case 2:
      ret = "charging";
      break;
    case 3:
      ret = "full";
      break;
    default:
      break;
  }
  return ret;
}

function getScreenInfo() {
  var screen = UIScreen.mainScreen();
  var bounds = screen.bounds();
  var size = bounds[1]; //bounds is a CGRect struct
  var scale = screen.scale();
  var brightness = screen.brightness();
  // var nativeScale = screen.nativeScale();
  // var currentModesize = screen.currentMode().size();
  var nativeSize= screen.nativeBounds()[1];
  return {
    width_in_points: size[0],
    height_in_points: size[1],
    scale: scale,
    width_in_pixels: nativeSize[0],
    height_in_pixels: nativeSize[1],
    brightness: brightness,
  };
}

function getProcessInfo() {
  var NSProcessInfo = ObjC.classes.NSProcessInfo;
  var processInfo = NSProcessInfo.processInfo();
  return {
    host_name: processInfo.hostName().toString(),
    process_name: processInfo.processName().toString(),
    processid: processInfo.processIdentifier(), //or use frida API: Process.id
    osversion_str: processInfo.operatingSystemVersionString().toString(),
    arch: Process.arch,
    platform: Process.platform,
    pagesize: Process.pageSize,
    pointersize: Process.pointerSize
  };
}

function bundleIdentifier() {
  return mainBundle.bundleIdentifier().toString();
}

function getAppPathInfo() {
  return {
    bundle_path: mainBundle.bundlePath().toString(),
    sharedframework_path: mainBundle.sharedFrameworksPath().toString(),
    privateframework_path: mainBundle.privateFrameworksPath().toString(),
    executable_path: NSBundle.mainBundle().executablePath().toString(),
    receipt_path: mainBundle.appStoreReceiptURL().path().toString(),
    homedir: homeDirectory(),
    docdir: documentDirectory(),
    tempidr: temporaryDirectory(),
    cachesdir: cachesDirectory(),
    librarydir: libraryDirectory(),
    executable_file: mainBundleInfoForKey("CFBundleExecutable")
  };
}


function getCookies() {
  var cookieJar = {};
  var cookies = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage().cookies();
  for (var index = 0, cnt = cookies.count(); index < cnt; index++) {
    var cookie = cookies.objectAtIndex_(index);
    var name = cookie.name().toString();
    var value = cookie.value().toString();
    cookieJar[name] = value;
  }
  return cookieJar;
}

function isJailbroken() {
  var files = [
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/usr/bin/ssh",
    "/etc/apt",
  ];
  var ret = false;
  // files.forEach((element) => {
  //   ret = ret || defaultFileManager.fileExistsAtPath_(element);
  // });

  files.forEach(function (element, index) {
    ret = ret || defaultFileManager.fileExistsAtPath_(element);
  });
  return ret;
}

function sysctlStringValueByName(name) {
  var cname = Memory.allocUtf8String(name);
  var psize = Memory.alloc(8); // a size pointer
  Memory.writeUInt(psize, 0); // the default size is equal to 0
  var ret = sysctlbyname(cname, NULL, psize, NULL, 0);
  var sizevalue = Memory.readUInt(psize);
  if (ret != 0 || sizevalue == 0) {
    send({
      error_code: ret,
      size: sizevalue,
      message: "call sysctlbyname to get target size failed.",
    });
    return "";
  }

  var pvalue = Memory.alloc(sizevalue);
  ret = sysctlbyname(cname, pvalue, psize, NULL, 0);
  if (ret == 0) {
    return pvalue.readUtf8String();
  } else {
    send({
      error_code: ret,
      message: "call sysctlbyname to get target value failed.",
    });
  }
}

function sysctlInt32ValueByName(name) {
  var cname = Memory.allocUtf8String(name);
  var psize = Memory.alloc(4); // a int32 pointer
  Memory.writeInt(psize, 4); // size value is equal to 4 bytes

  var pvalue = Memory.alloc(4);
  Memory.writeInt(pvalue, 0);
  var ret = sysctlbyname(cname, pvalue, psize, NULL, 0);
  if (ret == 0) {
    return pvalue.readS32();
  } else {
    send({
      error_code: ret,
      message: "call sysctlInt32ValueByName to get target value failed.",
    });
  }
}

function sysctlInt64ValueByName(name) {
  var cname = Memory.allocUtf8String(name);
  var psize = Memory.alloc(8); // a int64 pointer
  Memory.writeInt(psize, 8); // size value is equal to 8 bytes

  var pvalue = Memory.alloc(8);
  Memory.writeInt(pvalue, 0);
  var ret = sysctlbyname(cname, pvalue, psize, NULL, 0);
  if (ret == 0) {
    return pvalue.readS64();
  } else {
    send({
      error_code: ret,
      message: "call sysctlInt64ValueByName to get target value failed.",
    });
  }
}

function sysctlUInt64ValueByName(name) {
  var cname = Memory.allocUtf8String(name);
  var psize = Memory.alloc(8); // a unsigned int64 pointer
  Memory.writeInt(psize, 8); // the unsigned int64 size is equal to 8 bytes

  var pvalue = Memory.alloc(8);
  Memory.writeInt(pvalue, 0);
  var ret = sysctlbyname(cname, pvalue, psize, NULL, 0);
  if (ret == 0) {
    return pvalue.readU64();
  } else {
    send({
      error_code: ret,
      message: "call sysctlUInt64ValueByName to get target value failed.",
    });
  }
}

function getCarrierInfo() {
  var ctinfo = ObjC.classes.CTTelephonyNetworkInfo.alloc().init();
  var carrier = ctinfo.subscriberCellularProvider();
  var name = carrier.carrierName().toString();
  var countryCode = carrier.mobileCountryCode().toString();
  var isoCountryCode = carrier.isoCountryCode().toString();
  return {
    carrier_name: name,
    country_code: countryCode,
    iso_country_code: isoCountryCode,
  };
}

function getAppModuleInfo() {
  var moduleInfo = [];
  Process.enumerateModulesSync().forEach(function (image) {
    if (image.path.indexOf(".app") != -1 || image.path.indexOf("/Library/MobileSubstrate/") == 0) {
      moduleInfo.push({
        name: image.name,
        path: image.path,
        baseaddr: image.base,
        size: image.size
      });
    }
  });
  // return JSON.stringify(moduleInfo, null, 2);
  return moduleInfo;
}

rpc.exports = {
  devicename: deviceName,
  systemname: systemName,
  systemversion: systemVersion,
  model: deviceModel,
  localizedmodel: localizedModel,
  idfv: identifierForVendor,
  idfa: advertisingIdentifier,
  batterylevel: batteryLevel,
  batterystate: batteryState,
  bundleid: bundleIdentifier,
  username: userName,
  fullusername: fullUserName,
  isjailbroken: isJailbroken,
  sysctlstringbyname: sysctlStringValueByName,
  sysctlint32valuebyname: sysctlInt32ValueByName,
  sysctlint64valuebyname: sysctlInt64ValueByName,
  sysctluint64valuebyname: sysctlUInt64ValueByName,
  storagesize: storageSize,
  freesize: freeSize,
  mainbundleinfoforkey: mainBundleInfoForKey,
  carrierinfo: getCarrierInfo,
  screeninfo: getScreenInfo,
  moduleinfo: getAppModuleInfo,
  apppathinfo: getAppPathInfo,
  processinfo: getProcessInfo,
  cookies: getCookies,
};
