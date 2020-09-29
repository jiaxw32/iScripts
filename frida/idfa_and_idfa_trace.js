var bundle = ObjC.classes.NSBundle.mainBundle();
var jsIdentifier = bundle.bundleIdentifier().toString();

console.log("App Bundle Identifier: " + jsIdentifier);

Interceptor.attach(ObjC.classes.ASIdentifierManager["- advertisingIdentifier"].implementation, {
  onLeave: function (retval) {
    var idfa = ObjC.Object(retval).UUIDString().toString();
    console.log(jsIdentifier + " IDFA: " + idfa);
  }
});

Interceptor.attach(ObjC.classes.UIDevice["- identifierForVendor"].implementation, {
  onLeave: function (retval) {
    var idfv = ObjC.Object(retval).UUIDString().toString();
    console.log(jsIdentifier + " IDFV: " + idfv);
  }
});