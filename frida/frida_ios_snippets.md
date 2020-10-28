# Frida iOS snippets

## OC 对象转换为 js json 字符串

```javascript
function convertNSObjectToJSString(obj) {
    var NSString = ObjC.classes.NSString;
    var NSMutableDictionary = ObjC.classes.NSMutableDictionary;
    var NSJSONSerialization = ObjC.classes.NSJSONSerialization;
    // var NSError = ObjC.classes.NSError;

    var valid = NSJSONSerialization.isValidJSONObject_(obj);
    if (!valid) return null;

    const NSJSONWritingPrettyPrinted = 1;
    const NSUTF8StringEncoding = 4;

    // new a NSError* pointer, initialize to NULL
    var errorPtr = Memory.alloc(Process.pointerSize);
    Memory.writePointer(errorPtr, NULL);

    var data = NSJSONSerialization.dataWithJSONObject_options_error_(obj, NSJSONWritingPrettyPrinted, errorPtr);
    var error = Memory.readPointer(errorPtr);
    if (error.isNull()) {
        var str = NSString.alloc().initWithData_encoding_(data, NSUTF8StringEncoding);
        return str.toString();
    } else {
        var errorObj = new ObjC.Object(error);
        console.log(errorObj.toString());
        return null;
    }
}
```
