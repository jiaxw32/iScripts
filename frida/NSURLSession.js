
var NSURLSession = ObjC.classes.NSURLSession;

var dataTaskWithRequest_ = NSURLSession['- dataTaskWithRequest:'];
var dataTaskWithURL_ = NSURLSession['- dataTaskWithURL:'];
var dataTaskWithRequest_completionHandler_ = NSURLSession['- dataTaskWithRequest:completionHandler:'];
var dataTaskWithURL_completionHandler_ = NSURLSession['- dataTaskWithURL:completionHandler:'];

Interceptor.attach(dataTaskWithRequest_.implementation, {
    onEnter: function (args, state) {
      var request = ObjC.Object(args[2]);
      var url = request.URL();
      console.log("dataTaskWithRequest_ url: " + url.toString());
    }
});

Interceptor.attach(dataTaskWithURL_.implementation, {
    onEnter: function (args, state) {
      var url = ObjC.Object(args[2]);
      console.log("dataTaskWithURL_ url: " + url.toString());
    }
});

Interceptor.attach(dataTaskWithRequest_completionHandler_.implementation, {
    onEnter: function (args, state) {
        var request = ObjC.Object(args[2]);
        var url = request.URL();
        console.log("dataTaskWithRequest_completionHandler_ url: " + url.toString());
    }
});

Interceptor.attach(dataTaskWithURL_completionHandler_.implementation, {
    onEnter: function (args, state) {
        var url = ObjC.Object(args[2]);
        console.log("dataTaskWithURL_completionHandler_ url: " + url.toString());
    }
});

var uploadTaskWithRequest_fromFile_ = NSURLSession['- uploadTaskWithRequest:fromFile:'];
var uploadTaskWithRequest_fromData_ = NSURLSession['- uploadTaskWithRequest:fromData:'];
var uploadTaskWithStreamedRequest_ = NSURLSession['- uploadTaskWithStreamedRequest:'];
var uploadTaskWithRequest_fromFile_completionHandler_ = NSURLSession['- uploadTaskWithRequest:fromFile:completionHandler:'];
var uploadTaskWithRequest_fromData_completionHandler_ = NSURLSession['- uploadTaskWithRequest:fromData:completionHandler:'];


Interceptor.attach(uploadTaskWithRequest_fromFile_.implementation, {
    onEnter: function (args, state) {
        var request = ObjC.Object(args[2]);
        var url = request.URL();
        var fileURL = ObjC.Object(args[3]);
        console.log("uploadTaskWithRequest_fromFile_: " + url.toString() + ", file url: " + fileURL.toString());
    }
});

Interceptor.attach(uploadTaskWithRequest_fromData_.implementation, {
    onEnter: function (args, state) {
        var request = ObjC.Object(args[2]);
        var url = request.URL();
        var data = ObjC.Object(args[3]);
        console.log("uploadTaskWithRequest_fromData_ url: " + url.toString());
    }
});

Interceptor.attach(uploadTaskWithStreamedRequest_.implementation, {
    onEnter: function (args, state) {
        var request = ObjC.Object(args[2]);
        var url = request.URL();
        console.log("uploadTaskWithStreamedRequest_ url: " + url.toString());
    }
});

Interceptor.attach(uploadTaskWithRequest_fromFile_completionHandler_.implementation, {
    onEnter: function (args, state) {
        var request = ObjC.Object(args[2]);
        var url = request.URL();

        var fileURL = ObjC.Object(args[3]);
        console.log("uploadTaskWithRequest_fromFile_completionHandler_ url: " + url.toString() + ", file url: " + fileURL.toString());
    }
});

Interceptor.attach(uploadTaskWithRequest_fromData_completionHandler_.implementation, {
    onEnter: function (args, state) {
        var request = ObjC.Object(args[2]);
        var url = request.URL();
        console.log("uploadTaskWithRequest_fromData_completionHandler_ url: " + url.toString());
    }
});

var downloadTaskWithRequest_ = NSURLSession['- downloadTaskWithRequest:'];
var downloadTaskWithURL_ = NSURLSession['- downloadTaskWithURL:'];
var downloadTaskWithRequest_completionHandler_ = NSURLSession['- downloadTaskWithRequest:completionHandler:'];
var downloadTaskWithURL_completionHandler = NSURLSession['- downloadTaskWithURL:completionHandler:'];
var downloadTaskWithResumeData_completionHandler_ = NSURLSession['- downloadTaskWithResumeData:completionHandler:'];

Interceptor.attach(downloadTaskWithRequest_.implementation, {
    onEnter: function (args, state) {
        var request = ObjC.Object(args[2]);
        var url = request.URL();
        console.log("downloadTaskWithRequest_: " + url.toString());
    }
});

Interceptor.attach(downloadTaskWithURL_.implementation, {
    onEnter: function (args, state) {
        var url = ObjC.Object(args[2]);
        console.log("downloadTaskWithURL_ url: " + url.toString());
    }
});

Interceptor.attach(downloadTaskWithRequest_completionHandler_.implementation, {
    onEnter: function (args, state) {
        var request = ObjC.Object(args[2]);
        var url = request.URL();
        console.log("downloadTaskWithRequest_completionHandler_ url: " + url.toString());
    }
});

Interceptor.attach(downloadTaskWithURL_completionHandler.implementation, {
    onEnter: function (args, state) {
        var url = ObjC.Object(args[2]);
        console.log("downloadTaskWithURL_completionHandler url: " + url.toString());
    }
});

Interceptor.attach(downloadTaskWithResumeData_completionHandler_.implementation, {
    onEnter: function (args, state) {
        var request = ObjC.Object(args[2]);
        var url = request.URL();
        console.log("downloadTaskWithResumeData_completionHandler_ url: " + url.toString());
    }
});
//  Interceptor.attach(requestForJSONWithURL.implementation, {
//   onEnter: function (args, state) {
//     // console.log('-[TTNetworkManagerChromium requestForJSONWithURL_:' + args[2] + ' params:' + args[3] + ' method:' + args[4] + ' needCommonParams:' + args[5] + ' headerField:' + args[6] + ' requestSerializer:' + args[7] + ' responseSerializer:' + args[8] + ' autoResume:' + args[9] + ' verifyRequest:' + args[10] + ' isCustomizedCookie:' + args[11] + ' callback:' + args[12] + ' callbackWithResponse:' + args[13] + ' dispatch_queue:' + args[14] + ']');
//     var url = ObjC.Object(args[2]);
//     console.log(url.toString());
//     // Process.enumerateModulesSync().forEach(function(e){if(e.path.indexOf('.app')!=-1){console.log(e.path)}})
//     // log('\tBacktrace:\n\t' + Thread.backtrace(this.context,Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
//   }
// });