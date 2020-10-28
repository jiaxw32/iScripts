if (ObjC.available) {
  var NSString = ObjC.classes.NSString;
  var NSMutableDictionary = ObjC.classes.NSMutableDictionary;
  var NSJSONSerialization = ObjC.classes.NSJSONSerialization;
  const NSUTF8StringEncoding = 4;

  function convertNSObjectToJSString(obj) {
    var valid = NSJSONSerialization.isValidJSONObject_(obj);
    if (!valid) return null;
    const NSJSONWritingPrettyPrinted = 1;
    var NSError = ObjC.classes.NSError;
    var errorPtr = Memory.alloc(Process.pointerSize);
    Memory.writePointer(errorPtr, NULL); // initialize to NULL
    var data = NSJSONSerialization.dataWithJSONObject_options_error_(
      obj,
      NSJSONWritingPrettyPrinted,
      errorPtr
    );
    var error = Memory.readPointer(errorPtr);
    if (error.isNull()) {
      var str = NSString.alloc().initWithData_encoding_(
        data,
        NSUTF8StringEncoding
      );
      return str.toString();
    } else {
      var errorObj = new ObjC.Object(error); // now you can treat errorObj as an NSError instance
      console.log(errorObj.toString());
      return null;
    }
  }

  function printMethodsOfClass(nsclass) {
    var name = nsclass.toString();
    console.log('================================= ' + name + ' methods begin =================================');
    nsclass.$ownMethods.forEach((element) => {
      console.log(element);
    });
    console.log('================================= ' + name + ' methods end =================================');
  }

  if ("AFHTTPSessionManager" in ObjC.classes) {
    var pendingBlocks = [];
    var AFHTTPSessionManager = ObjC.classes.AFHTTPSessionManager;
    printMethodsOfClass(AFHTTPSessionManager);
    var dataTaskWithHTTPMethod_ =
      AFHTTPSessionManager[
        "- dataTaskWithHTTPMethod:URLString:parameters:headers:uploadProgress:downloadProgress:success:failure:"
      ];
    if (typeof dataTaskWithHTTPMethod_ == 'undefined') {
      console.log('-[AFHTTPSessionManager dataTaskWithHTTPMethod:URLString:parameters:headers:uploadProgress:downloadProgress:success:failure:] undefined.');
    } else {
      Interceptor.attach(dataTaskWithHTTPMethod_.implementation, {
        onEnter: function (args, state) {
          // var method = ObjC.Object(args[2]);
          // var url = ObjC.Object(args[3]);
          // var params = ObjC.Object(args[4]);
          // if (NSJSONSerialization.isValidJSONObject_(params)) {
          //   params = convertNSObjectToJSString(params);
          // }
          // var headers = ObjC.Object(args[5]);
          // if (NSJSONSerialization.isValidJSONObject_(headers)) {
          //   headers = convertNSObjectToJSString(headers);
          // }
  
          var successBlock = new ObjC.Block(args[8]);
          pendingBlocks.push(successBlock);
          var successBlockIMP = successBlock.implementation;
          successBlock.implementation = function (task, response) {
            var responseObject = ObjC.Object(response);
            var nstask = ObjC.Object(task);
            var request = nstask.currentRequest();
            var jsurl = request.URL().absoluteString().toString();
            var jsmethod = request.HTTPMethod().toString();
            var headerFields = request.allHTTPHeaderFields();
            var httpBody = request.HTTPBody();
            var body = NSString.alloc().initWithData_encoding_(httpBody, NSUTF8StringEncoding);
            if (NSJSONSerialization.isValidJSONObject_(responseObject)) {
              responseObject = convertNSObjectToJSString(responseObject);
            }
            console.log(
              "-[AFHTTPSessionManager dataTaskWithHTTPMethod:URLString:parameters:headers:uploadProgress:downloadProgress:success:failure:] success callback\n" +
                "url: " + jsurl + "\n" +
                "method: " + jsmethod + "\n" +
                "headers: " + convertNSObjectToJSString(headerFields) + "\n" +
                "body: " + body + '\n' +
                "response: " + responseObject
            );
            successBlockIMP(task, response);
            const idx = pendingBlocks.indexOf(successBlock);
            delete pendingBlocks[idx];
          };
          // console.log(
          //   `-[AFHTTPSessionManager dataTaskWithHTTPMethod:URLString:parameters:headers:uploadProgress:downloadProgress:success:failure:]\nurl: ${url}\nmethod: ${method}\nparams: ${params}\nheaders: ${headers}`
          // );
        },
      });
    }

    var postWithConstructBody =
      AFHTTPSessionManager[
        "- POST:parameters:headers:constructingBodyWithBlock:progress:success:failure:"
      ];
    if (typeof postWithConstructBody == 'undefined') {
      console.log('-[AFHTTPSessionManager POST:parameters:headers:constructingBodyWithBlock:progress:success:failure:] undefined.');
    } else {
      Interceptor.attach(postWithConstructBody.implementation, {
        onEnter: function (args, state) {
          var url = ObjC.Object(args[2]);
          var params = ObjC.Object(args[3]);
          if (NSJSONSerialization.isValidJSONObject_(params)) {
            params = convertNSObjectToJSString(params);
          }
          var headers = ObjC.Object(args[4]);
          if (NSJSONSerialization.isValidJSONObject_(headers)) {
            headers = convertNSObjectToJSString(headers);
          }
  
          var successBlock = new ObjC.Block(args[7]);
          var successBlockIMP = successBlock.implementation;
          successBlock.implementation = function (task, response) {
            var responseObject = ObjC.Object(response);
            var nstask = ObjC.Object(task);
            var request = nstask.currentRequest();
            var jsurl = request.URL().absoluteString().toString();
            if (NSJSONSerialization.isValidJSONObject_(responseObject)) {
              responseObject = convertNSObjectToJSString(responseObject);
            }
            console.log(
              "-[AFHTTPSessionManager POST:parameters:headers:constructingBodyWithBlock:progress:success:failure:] success callback\nurl:" +
                jsurl +
                "\n" +
                responseObject
            );
            successBlockIMP(task, response);
          };
          console.log(
            `-[AFHTTPSessionManager POST:parameters:headers:constructingBodyWithBlock:progress:success:failure:]\nurl: ${url}\nparams: ${params}\nheaders: ${headers}`
          );
        },
      });
    }
  } else {
    console.log("the current app doesn't include AFHTTPSessionManager class.");
  }
} else {
  console.log("objc runtime not available.");
}
