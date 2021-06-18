
if (ObjC.available) {
    var kSecConstants = {
        "ck": "kSecAttrAccessibleAfterFirstUnlock",
        "ak": "kSecAttrAccessibleWhenUnlocked",
        "cku": "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
        "dk": "kSecAttrAccessibleAlways",
        "dku": "kSecAttrAccessibleAlwaysThisDeviceOnly",
        "akpu": "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly",
        "aku": "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
        "ck": "kSecAttrAccessibleAfterFirstUnlock",
        "cku": "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
        "dk": "kSecAttrAccessibleAlways",
        "akpu": "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly",
        "ak": "kSecAttrAccessibleWhenUnlocked",
        "aku": "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
        "dku": "kSecAttrAccessibleAlwaysThisDeviceOnly",
        "cert": "kSecClassCertificate",
        "class": "kSecClass",
        "genp": "kSecClassGenericPassword",
        "idnt": "kSecClassIdentity",
        "inet": "kSecClassInternetPassword",
        "keys": "kSecClassKey",
    }
    var SecItemCopyMatching = new NativeFunction(ptr(Module.findExportByName("Security", "SecItemCopyMatching")), 'pointer', ['pointer', 'pointer']);

    var query = ObjC.classes.NSMutableDictionary.dictionary();
    query.addObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true), "r_Attributes");
    query.addObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true), "r_Ref");
    query.addObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true), "r_Data");
    query.addObject_forKey_("m_LimitAll", "m_Limit");
    
    var NSKeyedUnarchiver = ObjC.classes.NSKeyedUnarchiver;
    var secItemClasses = ["genp", "inet", "cert", "keys", "idnt"];
    var secItemClass;
    for (const secItemClassIter in secItemClasses) {
        var key = secItemClasses[secItemClassIter];
        console.log('-------------- ' + key + ' data -------------- ')
        var datalist = [];
        query.setObject_forKey_(key, "class");
        var resultPtr = Memory.alloc(Process.pointerSize);
        Memory.writePointer(resultPtr, NULL);
        if (SecItemCopyMatching(query, resultPtr) == 0) {
            var result = new ObjC.Object(Memory.readPointer(resultPtr));
            for (var i = 0; i < result.count(); i++) {
                var entry = result.objectAtIndex_(i);
                // console.log(entry);

                var nsdata = ObjC.Object(entry.objectForKey_("v_Data"));
                var objdata = NSKeyedUnarchiver.unarchiveObjectWithData_(nsdata);

                datalist.push(JSON.stringify({
                    EntitlementGroup: entry.objectForKey_("agrp").valueOf(),
                    Service: (entry.objectForKey_("svce") ? entry.objectForKey_("svce").valueOf() : "null"),
                    Account: (entry.objectForKey_("acct") ? entry.objectForKey_("acct").valueOf() : "null"),
                    Data: objdata ? objdata.toString() : "",
                    Protection: kSecConstants[entry.objectForKey_("pdmn")].valueOf(),
                    CreationTime: entry.objectForKey_("cdat").valueOf(), // 创建日期
                    ModifiedTime: entry.objectForKey_("mdat").valueOf(), // 修改日期
                    kSecClass: kSecConstants[secItemClasses[secItemClassIter]]
                }, null, 2));
            }
        }
        console.log(datalist);
    }
} else {
    console.log("Objective-C Runtime is not available!");
}

/*
{
    UUID = "A274C815-CA4D-45D6-8AE8-AB5D9BA2F0EE";
    accc = "<SecAccessControlRef: cku>";
    acct = "1:290083110544:ios:a2dad3ea75b0caa5922215__FIRAPP_DEFAULT";
    agrp = "NR2KD6K4TL.com.jiangjia.gif";
    cdat = "2021-04-08 11:12:29 +0000";
    class = genp;
    mdat = "2021-06-18 07:24:39 +0000";
    musr = {length = 0, bytes = 0x};
    pdmn = cku;
    persistref = {length = 0, bytes = 0x};
    sha1 = {length = 20, bytes = 0xd55c91e8c2ee3f18cd1e1cfa3df5a2123b7d410c};
    svce = "com.firebase.FIRInstallations.installations";
    sync = 0;
    tomb = 0;
    "v_Data" = {length = 1047, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 00000389 };
}
*/