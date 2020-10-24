Module.ensureInitialized("UIKit");

function hexString(num) {
  return "0x" + num.toString(16);
}

function getU32(addr) {
  if (typeof addr == "number") {
    addr = ptr(addr);
  }
  return Memory.readU32(addr);
}

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

var _dyld_get_image_header = exportFunction(
  "f",
  "_dyld_get_image_header",
  "pointer",
  ["uint"]
);

var _dyld_get_image_vmaddr_slide = exportFunction(
  "f",
  "_dyld_get_image_vmaddr_slide",
  "long",
  ["uint"]
);

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

function getUserInfo() {
  return {
    username: ObjC.Object(NSUserName()).toString(),
    fullusername: ObjC.Object(NSFullUserName()).toString(),
  };
}

// console.log(JSON.stringify(getUserInfo()));

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

var NSBundle = ObjC.classes.NSBundle;
var mainBundle = NSBundle.mainBundle();

var NSFileManager = ObjC.classes.NSFileManager;
var defaultFileManager = NSFileManager.defaultManager();

function mainBundleInfoForKey(key) {
  var value = mainBundle.infoDictionary().objectForKey_(key);
  return value ? value.toString() : "null";
}

function getAppBaseInfo() {
  var ret = {
    bundleid: mainBundle.bundleIdentifier().toString(),
    appname: mainBundleInfoForKey("CFBundleDisplayName"),
    bundlename: mainBundleInfoForKey("CFBundleName"),
    app_version: mainBundleInfoForKey("CFBundleVersion"),
    short_version: mainBundleInfoForKey("CFBundleShortVersionString"),
    idfv: identifierForVendor(),
    executable_file: mainBundleInfoForKey("CFBundleExecutable"),
    bundle_path: mainBundle.bundlePath().toString(),
    docdir: documentDirectory(),
  };
  if ("ASIdentifierManager" in ObjC.classes) {
    ret["idfa"] = advertisingIdentifier();
  }
  return ret;
}

function getDeviceInfo() {
  var currentDevice = UIDevice.currentDevice();
  const deviceName = currentDevice.name().toString();
  const systemName = currentDevice.systemName().toString();
  const systemVersion = currentDevice.systemVersion().toString();
  const deviceModel = currentDevice.model().toString();
  const localizedModel = currentDevice.localizedModel().toString();
  var ret = {
    device_name: deviceName,
    system_name: systemName,
    system_version: systemVersion,
    device_model: deviceModel,
    device_localized_model: localizedModel,
    battery_info: getBatteryInfo(),
    idfa: advertisingIdentifier(),
    jailbroken: isJailbroken(),
    screen_info: getScreenInfo(),
    carrier_info: getCarrierInfo(),
    free_size: freeSize(),
    storage_size: storageSize(),
    hw_model: sysctlStringValueByName("hw.model"),
    hw_machine: sysctlStringValueByName("hw.machine"),
    hw_machine: sysctlStringValueByName("kern.version"),
    kern_osversion: sysctlStringValueByName("kern.osversion"),
    hw_cputype: sysctlInt32ValueByName("hw.cputype"),
    hw_cpusubtype: sysctlInt32ValueByName("hw.cpusubtype"),
    hw_memsize: sysctlInt64ValueByName("hw.memsize"),
  };
  return ret;
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
    send({ message: "current app doesn't support AdSupport module." });
    return "";
  }
}

function getBatteryInfo() {
  const currentDevice = UIDevice.currentDevice();
  const batteryMonitoringEnabled = currentDevice.isBatteryMonitoringEnabled();
  // Battery level ranges from 0.0 (fully discharged) to 1.0 (100% charged). Before accessing this property, ensure that battery monitoring is enabled.
  // If battery monitoring is not enabled, the value of this property is –1.0.
  const batteryLevel = currentDevice.batteryLevel();
  const batteryState = currentDevice.batteryState().valueOf();
  var state = "unknown";
  switch (batteryState) {
    case 0:
      state = "unknown";
      break;
    case 1:
      state = "unplugged";
      break;
    case 2:
      state = "charging";
      break;
    case 3:
      state = "full";
      break;
    default:
      break;
  }

  return {
    monitoring_enabled: batteryMonitoringEnabled,
    battery_level: batteryLevel,
    state: state
  }
}

function getScreenInfo() {
  var screen = UIScreen.mainScreen();
  var bounds = screen.bounds();
  var size = bounds[1]; //bounds is a CGRect struct
  var scale = screen.scale();
  var brightness = screen.brightness();
  // var nativeScale = screen.nativeScale();
  // var currentModesize = screen.currentMode().size();
  var nativeSize = screen.nativeBounds()[1];
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
    pointersize: Process.pointerSize,
  };
}

function getAppPathInfo() {
  var ret = {
    bundle_path: mainBundle.bundlePath().toString(),
    sharedframework_path: mainBundle.sharedFrameworksPath().toString(),
    privateframework_path: mainBundle.privateFrameworksPath().toString(),
    executable_path: NSBundle.mainBundle().executablePath().toString(),
    homedir: homeDirectory(),
    docdir: documentDirectory(),
    tempidr: temporaryDirectory(),
    cachesdir: cachesDirectory(),
    librarydir: libraryDirectory(),
  };
  var receiptURL = mainBundle.appStoreReceiptURL();
  if (receiptURL) {
    ret["receipt_path"] = receiptURL.path().toString();
  }
  return ret;
}

function getCookies() {
  var cookieJar = [];
  var cookies = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage().cookies();
  for (var index = 0, cnt = cookies.count(); index < cnt; index++) {
    var cookie = cookies.objectAtIndex_(index);
    cookieJar.push({
      domain: cookie.domain().toString(),
      expiresDate: cookie.expiresDate()
        ? cookie.expiresDate().toString()
        : "null",
      isHTTPOnly: cookie.isHTTPOnly().toString(),
      isSecure: cookie.isSecure().toString(),
      name: cookie.name().toString(),
      path: cookie.path().toString(),
      value: cookie.value().toString(),
      version: cookie.version().toString(),
    });
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
  var carrierName = carrier.carrierName();
  var countryCode = carrier.mobileCountryCode();
  var isoCountryCode = carrier.isoCountryCode();
  var networkCode = carrier.mobileNetworkCode();
  return {
    carrier_name: carrierName ? carrierName.toString() : null,
    country_code: countryCode ? countryCode.toString() : null,
    iso_country_code: isoCountryCode ? isoCountryCode.toString() : null,
    network_code: networkCode ? networkCode.toString() : null,
  };
}

function getAppModuleInfo() {
  var moduleInfo = [];
  Process.enumerateModulesSync().forEach(function (image, index) {
    if (
      image.path.indexOf(".app") !=
      -1 /* ||
      image.path.indexOf("/Library/MobileSubstrate/") == 0 */
    ) {
      var slide = _dyld_get_image_vmaddr_slide(index);
      var macho_file_info = getMachOFileInfo(image.base);
      var hex_slide = "0x" + slide.toString(16);
      moduleInfo.push({
        name: image.name,
        path: image.path,
        baseaddr: image.base,
        size: image.size,
        addr_slide: hex_slide,
        macho: macho_file_info,
      });
    }
  });
  // return JSON.stringify(moduleInfo, null, 2);
  return moduleInfo;
}

function getAllBundleInfo(type) {
  var frameworks;
  if (type == 0) {
    frameworks = ObjC.classes.NSBundle.allBundles();
  } else {
    frameworks = ObjC.classes.NSBundle.allFrameworks();
  }
  var appBundles = [];
  for (var i = 0; i < frameworks.count().valueOf(); i++) {
    var bundle = frameworks.objectAtIndex_(i);
    var bundleInfo = bundle.infoDictionary();
    var bundleIdentifier = bundleInfo.objectForKey_("CFBundleIdentifier");
    var bundleVersion = bundleInfo.objectForKey_("CFBundleShortVersionString");
    var bundleExecutable = bundleInfo.objectForKey_("CFBundleExecutable");
    appBundles.push({
      path: bundle.bundlePath().toString(),
      id: bundleIdentifier ? bundleIdentifier.toString() : null,
      version: bundleVersion ? bundleVersion.toString() : null,
      executable: bundleExecutable ? bundleExecutable.toString() : null,
    });
  }
  return appBundles;
}

var FAT_MAGIC = 0xcafebabe;
var FAT_CIGAM = 0xbebafeca;
var MH_MAGIC = 0xfeedface;
var MH_CIGAM = 0xcefaedfe;
var MH_MAGIC_64 = 0xfeedfacf;
var MH_CIGAM_64 = 0xcffaedfe;

/* ARM CPU type */
var CPU_ARCH_ABI64 = 0x01000000; //64 bit ABI
var CPU_TYPE_ARM = 12;
var CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64;

/* ARM64 subtypes */
var CPU_SUBTYPE_ARM64_ALL = 0;
var CPU_SUBTYPE_ARM64_V8 = 1;

/* ARM subtypes */
var CPU_SUBTYPE_ARM_ALL = 0;
var CPU_SUBTYPE_ARM_V4T = 5;
var CPU_SUBTYPE_ARM_V6 = 6;
var CPU_SUBTYPE_ARM_V5TEJ = 7;
var CPU_SUBTYPE_ARM_XSCALE = 8;
var CPU_SUBTYPE_ARM_V7 = 9;
var CPU_SUBTYPE_ARM_V7F = 10; /* Cortex A9 */
var CPU_SUBTYPE_ARM_V7S = 11; /* Swift */
var CPU_SUBTYPE_ARM_V7K = 12; /* Kirkwood40 */
var CPU_SUBTYPE_ARM_V8 = 13;

var LC_ENCRYPTION_INFO = 0x21;
var LC_ENCRYPTION_INFO_64 = 0x2c;
var LC_UUID = 0x1b;

/* Constants for the filetype field of the mach_header */
var MH_OBJECT = 0x1;
var MH_EXECUTE = 0x2;
var MH_FVMLIB = 0x3;
var MH_CORE = 0x4;
var MH_PRELOAD = 0x5;
var MH_DYLIB = 0x6;
var MH_DYLINKER = 0x7;
var MH_BUNDLE = 0x8;
var MH_DYLIB_STUB = 0x9;
var MH_DSYM = 0xa;
var MH_KEXT_BUNDLE = 0xb;

function getFileType(filetype) {
  var ret = "";
  switch (filetype) {
    case MH_OBJECT:
      ret = "MH_OBJECT";
      break;
    case MH_EXECUTE:
      ret = "MH_EXECUTE";
      break;
    case MH_FVMLIB:
      ret = "MH_FVMLIB";
      break;
    case MH_CORE:
      ret = "MH_CORE";
      break;
    case MH_PRELOAD:
      ret = "MH_PRELOAD";
      break;
    case MH_DYLIB:
      ret = "MH_DYLIB";
      break;
    case MH_DYLINKER:
      ret = "MH_DYLINKER";
    case MH_BUNDLE:
      ret = "MH_BUNDLE";
      break;
    case MH_DYLIB_STUB:
      ret = "MH_DYLIB_STUB";
      break;
    case MH_DSYM:
      ret = "MH_DSYM";
      break;
    case MH_KEXT_BUNDLE:
      ret = "MH_KEXT_BUNDLE";
      break;
    default:
      ret = hexString(cputype);
      break;
  }
  return ret;
}

function getCPUType(cputype) {
  var ret = "";
  switch (cputype) {
    case CPU_TYPE_ARM:
      ret = "CPU_TYPE_ARM";
      break;
    case CPU_TYPE_ARM64:
      ret = "CPU_TYPE_ARM64";
      break;
    default:
      ret = hexString(cputype);
      break;
  }
  return ret;
}

function getCPUSubtype(subtype) {
  var ret = "";
  switch (subtype) {
    case CPU_SUBTYPE_ARM_ALL:
      ret = "CPU_SUBTYPE_ARM_ALL";
      break;
    case CPU_SUBTYPE_ARM_V4T:
      ret = "CPU_SUBTYPE_ARM_V4T";
      break;
    case CPU_SUBTYPE_ARM_V6:
      ret = "CPU_SUBTYPE_ARM_V6";
      break;
    case CPU_SUBTYPE_ARM_V5TEJ:
      ret = "CPU_SUBTYPE_ARM_V5TEJ";
      break;
    case CPU_SUBTYPE_ARM_XSCALE:
      ret = "CPU_SUBTYPE_ARM_XSCALE";
      break;
    case CPU_SUBTYPE_ARM_V7:
      ret = "CPU_SUBTYPE_ARM_V7";
      break;
    case CPU_SUBTYPE_ARM_V7F:
      ret = "CPU_SUBTYPE_ARM_V7F";
      break;
    case CPU_SUBTYPE_ARM_V7S:
      ret = "CPU_SUBTYPE_ARM_V7S";
      break;
    case CPU_SUBTYPE_ARM_V7K:
      ret = "CPU_SUBTYPE_ARM_V7K";
      break;
    case CPU_SUBTYPE_ARM_V8:
      ret = "CPU_SUBTYPE_ARM_V8";
      break;
    default:
      ret = hexString(subtype);
      break;
  }
  return ret;
}

function getMachOFileInfo(addr) {
  if (addr == null) return {};

  // var mach_header = _dyld_get_image_header(0);
  var mach_header = addr;
  var ret = {};

  var magic = getU32(mach_header);
  var cputype = getU32(mach_header.add(0x4));
  var cpusubtype = getU32(mach_header.add(0x8));
  var filetype = getU32(mach_header.add(0xc));

  ret["magic_number"] = hexString(magic);
  ret["cputype"] = getCPUType(cputype);
  ret["cpusubtype"] = getCPUSubtype(cpusubtype);
  ret["filetype"] = getFileType(filetype);

  var size_of_mach_header = 0;
  if (magic == MH_MAGIC || magic == MH_CIGAM) {
    size_of_mach_header = 28;
  } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
    size_of_mach_header = 32;
  }

  var ncmds = getU32(mach_header.add(0x10));
  // var sizeofcmds = getU32(mach_header.add(0x14));
  var off = size_of_mach_header;
  for (var i = 0; i < ncmds; i++) {
    var cmd = getU32(mach_header.add(off));
    var cmdsize = getU32(mach_header.add(off + 4));
    if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
      var cryptid_off = off + 16;
      var cryptid = getU32(mach_header.add(cryptid_off));
      ret["cryptid"] = cryptid;
    } else if (cmd == LC_UUID) {
      var uuid_off = off + 8;
      var uuid = Memory.readByteArray(mach_header.add(uuid_off), 16);

      // console.log(hexdump(uuid, {
      //   offset: 0,
      //   length: 16,
      //   header: true,
      //   ansi: true
      // }));

      var arr = new Uint8Array(uuid);
      var str_uuid = "";
      for (var i = 0; i < arr.length; i++) {
        var num = arr[i];
        if (num < 16) {
          str_uuid += "0" + num.toString(16);
        } else {
          str_uuid += num.toString(16);
        }
      }
      ret["uuid"] = str_uuid.toUpperCase();
    }
    off += cmdsize;
  }
  return ret;
}

rpc.exports = {
  appbaseinfo: getAppBaseInfo,
  moduleinfo: getAppModuleInfo,
  apppathinfo: getAppPathInfo,
  processinfo: getProcessInfo,
  cookies: getCookies,
  allbundleinfo: getAllBundleInfo,
  deviceinfo: getDeviceInfo,
};
