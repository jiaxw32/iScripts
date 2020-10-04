Module.ensureInitialized("UIKit");
Module.ensureInitialized("CoreGraphics");
Module.ensureInitialized("AdSupport");

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

rpc.exports = {
  devicename: function () {
    return currentDevice.name().toString();
  },
  systemname: function () {
    return currentDevice.systemName().toString();
  },
  systemversion: function () {
    return currentDevice.systemVersion().toString();
  },
  model: function () {
    return currentDevice.model().toString();
  },
  localizedmodel: function () {
    return currentDevice.localizedModel().toString();
  },
  idfv: function () {
    return currentDevice.identifierForVendor().UUIDString().toString();
  },
  idfa: function(){
    return ASIdentifierManager.sharedManager().advertisingIdentifier().UUIDString().toString();
  },
  batterylevel: function () {
    // Battery level ranges from 0.0 (fully discharged) to 1.0 (100% charged). Before accessing this property, ensure that battery monitoring is enabled.
    // If battery monitoring is not enabled, the value of this property is –1.0.
    return currentDevice.batteryLevel();
  },
  batterystate: function () {
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
  },
  screenwidth: function () {
    var bounds = mainScreen.bounds();
    var size = bounds[1];
    return size[0];
  },
  screenheight: function () {
    var bounds = mainScreen.bounds(); //bounds is a CGRect struct
    var size = bounds[1];
    return size[1];
  },
  screenwidthinpixels: function () {
    var size = mainScreen.currentMode().size();
    return size[0];
  },
  screenheightinpixels: function () {
    var size = mainScreen.currentMode().size();
    return size[1];
  },
  scale: function () {
    return mainScreen.scale();
  },
  hostname: function () {
    return processInfo.hostName().toString();
  },
  processname: function () {
    return processInfo.processName().toString();
  },
  processid: function () {
    return processInfo.processIdentifier();
  },
  osversion: function () {
    return processInfo.operatingSystemVersionString().toString();
  },
  bundleid: function () {
    return mainBundle.bundleIdentifier().toString();
  },
  bundlename: function () {
    return bundleInfo.objectForKey_("CFBundleName").toString();
  },
  appname: function () {
    return bundleInfoForKey("CFBundleDisplayName");
  },
  executablefile: function () {
    return bundleInfoForKey("CFBundleExecutable");
  },
  appshortversion: function () {
    return bundleInfoForKey("CFBundleShortVersionString");
  },
  appversion: function () {
    return bundleInfoForKey("CFBundleVersion");
  },
};
