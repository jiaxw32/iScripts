Module.ensureInitialized("UIKit");
Module.ensureInitialized("CoreGraphics");

var UIDevice = ObjC.classes.UIDevice;
var currentDevice = UIDevice.currentDevice();

var UIScreen = ObjC.classes.UIScreen;
var mainScreen = UIScreen.mainScreen();

var NSProcessInfo = ObjC.classes.NSProcessInfo;
var processInfo = NSProcessInfo.processInfo();

var NSBundle = ObjC.classes.NSBundle;
var mainBundle = NSBundle.mainBundle();
var bundleInfo = mainBundle.infoDictionary();

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
    return mainScreen.bounds().size();
  },
  screenheight: function () {
    return mainScreen.bounds().size.height;
  },
  screen_width_in_pixels: function () {
    return mainScreen.currentMode().size().width();
  },
  screen_height_in_pixels: function () {
    return mainScreen.currentMode().size().height();
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
    return bundleInfo.objectForKey_("CFBundleDisplayName").toString();
  },
  executablefile: function () {
    return bundleInfo.objectForKey_("CFBundleExecutable").toString();
  },
  appshortversion: function () {
    return bundleInfo.objectForKey_("CFBundleShortVersionString").toString();
  },
  appversion: function () {
    return bundleInfo.objectForKey_("CFBundleVersion").toString();
  }
};
