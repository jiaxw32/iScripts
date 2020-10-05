Module.ensureInitialized("UIKit");
Module.ensureInitialized("CoreGraphics");
Module.ensureInitialized("AdSupport");

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

var NSSearchPathForDirectoriesInDomains = exportFunction("f", "NSSearchPathForDirectoriesInDomains", "pointer", ["int", "int", "int"]);
var NSHomeDirectory = exportFunction("f", "NSHomeDirectory", "pointer", []);
var NSTemporaryDirectory = exportFunction("f", "NSTemporaryDirectory", "pointer", []);
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
  var npdirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, 1);
  return ObjC.Object(npdirs).objectAtIndex_(0).toString();
}

function libraryDirectory() {
  var NSLibraryDirectory = 5;
  var NSUserDomainMask = 1;
  var npdirs = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, 1);
  return ObjC.Object(npdirs).objectAtIndex_(0).toString();
}

function cachesDirectory() {
  var NSCachesDirectory = 13;
  var NSUserDomainMask = 1;
  var npdirs = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, 1);
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

var UIDevice = ObjC.classes.UIDevice;
var currentDevice = UIDevice.currentDevice();

var UIScreen = ObjC.classes.UIScreen;
var mainScreen = UIScreen.mainScreen();

var NSProcessInfo = ObjC.classes.NSProcessInfo;
var processInfo = NSProcessInfo.processInfo();

var ASIdentifierManager = ObjC.classes.ASIdentifierManager;

var NSBundle = ObjC.classes.NSBundle;
var mainBundle = NSBundle.mainBundle();

function bundleInfoForKey(key) {
  return mainBundle.infoDictionary().objectForKey_(key).toString();
}

function deviceName(){
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

function advertisingIdentifier(){
  return ASIdentifierManager.sharedManager().advertisingIdentifier().UUIDString().toString();
}

function batteryLevel() {
  // Battery level ranges from 0.0 (fully discharged) to 1.0 (100% charged). Before accessing this property, ensure that battery monitoring is enabled.
  // If battery monitoring is not enabled, the value of this property is –1.0.
  return currentDevice.batteryLevel();
}

function batteryState() {
  var state = currentDevice.batteryState();
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

function screenWidth() {
  var bounds = mainScreen.bounds();
  var size = bounds[1];
  return size[0];
}

function screenHeight() {
  var bounds = mainScreen.bounds(); //bounds is a CGRect struct
  var size = bounds[1];
  return size[1];
}

function screenWidthInPixels() {
  var size = mainScreen.currentMode().size();
  return size[0];
}

function screenHeightInPixels() {
  var size = mainScreen.currentMode().size();
  return size[1];
}

function screenScale() {
  return mainScreen.scale();
}

function hostName() {
  return processInfo.hostName().toString();
}

function processName() {
  return processInfo.processName().toString();
}

function processIdentifier() {
  return processInfo.processIdentifier();
}

function osVersionString() {
  return processInfo.operatingSystemVersionString().toString();
}

function bundleIdentifier() {
  return mainBundle.bundleIdentifier().toString();
}

function bundlePath() {
  return mainBundle.bundlePath().toString();
}

function sharedFrameworksPath() {
  return mainBundle.sharedFrameworksPath().toString();
}

function privateFrameworksPath() {
  return mainBundle.privateFrameworksPath().toString();
}

function bundleName() {
  return bundleInfoForKey("CFBundleName").toString();
}

function bundleDisplayName() {
  return bundleInfoForKey("CFBundleDisplayName");
}

function executableFile() {
  return bundleInfoForKey("CFBundleExecutable");
}

function executablePath(){
  return NSBundle.mainBundle().executablePath().toString();
}

function receiptPath() {
  return mainBundle.appStoreReceiptURL().path().toString();
}

function appShortVersion() {
  return bundleInfoForKey("CFBundleShortVersionString");
}

function appVersion() {
  return bundleInfoForKey("CFBundleVersion");
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
  screenwidth: screenWidth,
  screenheight: screenHeight,
  screenwidthinpixels: screenWidthInPixels,
  screenheightinpixels: screenHeightInPixels,
  scale: screenScale,
  hostname: hostName,
  processname: processName,
  processid: processIdentifier,
  osversion: osVersionString,
  bundleid: bundleIdentifier,
  bundlename: bundleName,
  appname: bundleDisplayName,
  executablefile: executableFile,
  executablepath: executablePath,
  appshortversion: appShortVersion,
  appversion: appVersion,
  sharedframeworkspath: sharedFrameworksPath,
  privateframeworkspath: privateFrameworksPath,
  bundlepath: bundlePath,
  receiptpath: receiptPath,
  homedir: homeDirectory,
  docdir: documentDirectory,
  tempidr: temporaryDirectory,
  cachesdir: cachesDirectory,
  librarydir: libraryDirectory,
  username: userName,
  fullusername: fullUserName
};
