function stackBacktrace(ctx) {
  console.log(
    "\tBacktrace:\n\t" +
      Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .join("\n\t")
  );
}

// Get a reference to the openURL selector
var openURL = ObjC.classes.UIApplication["- openURL:"];

// Intercept the method
Interceptor.attach(openURL.implementation, {
  onEnter: function (args) {
    // As this is an Objective-C method, the arguments are as follows:
    // 0. 'self'
    // 1. The selector (openURL:)
    // 2. The first argument to the openURL method
    var myNSURL = new ObjC.Object(args[2]);
    // Convert it to a JS string
    var myJSURL = myNSURL.absoluteString().toString();
    // Log it
    console.log("-[UIApplication openURL:] >>> " + myJSURL);
    // stackBacktrace(this.context);
  },
});

Interceptor.attach(ObjC.classes.UIApplication["- canOpenURL:"].implementation, {
  onEnter: function (args) {
    var jsUrl = ObjC.Object(args[2]).toString();
    console.log("-[UIApplication canOpenURL:] >>> " + jsUrl);
    // stackBacktrace(this.context);
  },
});