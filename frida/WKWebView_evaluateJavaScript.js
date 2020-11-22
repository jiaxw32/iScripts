if (ObjC.available && "WKWebView" in ObjC.classes) {
  var WKWebView = ObjC.classes["WKWebView"];
  var evaluateJavaScript_ = WKWebView["- evaluateJavaScript:completionHandler:"];
  const pendingBlocks = [];
  Interceptor.attach(evaluateJavaScript_.implementation, {
      onEnter: function (args) {
        var script = ObjC.Object(args[2]);
        if (args[3]) {
          var handler = new ObjC.Block(args[3]);
          pendingBlocks.push(handler);
          const origCallback = handler.implementation;
          handler.implementation = function (result, err) {
            origCallback(result, err);
            console.log("evaluate JavaScript completion callback: ", result);
            var idx = pendingBlocks[handler];
            delete pendingBlocks[idx];
          };
        }
        console.log(`-[WVWKWebView evaluateJavaScript:completionHandler:]`, script.toString());
      },
    });
}
