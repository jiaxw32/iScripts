
if (ObjC.available) {
    // OSStatus SecItemCopyMatching(CFDictionaryRef query, CFTypeRef * __nullable CF_RETURNS_RETAINED result);
    var SecItemCopyMatching = new NativeFunction(ptr(Module.findExportByName("Security", "SecItemCopyMatching")), 'pointer', ['pointer', 'pointer']);

    // OSStatus SecItemDelete(CFDictionaryRef query)
    var SecItemDelete = new NativeFunction(ptr(Module.findExportByName("Security", "SecItemDelete")), 'pointer', ['pointer']);

    var query = ObjC.classes.NSMutableDictionary.dictionary();
    query.addObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true), "r_Attributes");
    query.addObject_forKey_("m_LimitAll", "m_Limit");
    
    var secItemClasses = ["genp", "inet", "cert", "keys", "idnt"];
    for (const idx in secItemClasses) {
        var key = secItemClasses[idx];
        query.setObject_forKey_(key, "class");

        var resultPtr = Memory.alloc(Process.pointerSize);
        Memory.writePointer(resultPtr, NULL);
        if (SecItemCopyMatching(query, resultPtr) == 0) {
            var spec = ObjC.classes.NSMutableDictionary.dictionary();
            spec.setObject_forKey_(key, "class");
            var status = SecItemDelete(spec);
            if (!status.toInt32()) {
                console.log('[delete] ' + key + ' data success.');
            } else {
                console.log('[delete] ' + key + ' data failed: ' + status.toInt32());
            }
        }
    }
} else {
    console.log("Objective-C Runtime is not available!");
}