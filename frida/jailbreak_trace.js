function stackBacktrace(ctx) {
  console.log(
    "\tBacktrace:\n\t" +
      Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .join("\n\t")
  );
}

const jailbreakPaths = [
  "/Applications/Cydia.app",
  "/Applications/FakeCarrier.app",
  "/Applications/Icy.app",
  "/Applications/IntelliScreen.app",
  "/Applications/MxTube.app",
  "/Applications/RockApp.app",
  "/Applications/SBSetttings.app",
  "/Applications/WinterBoard.app",
  "/Applications/blackra1n.app",
  "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
  "/Library/MobileSubstrate/MobileSubstrate.dylib",
  "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
  "/System/Library/LaunchDaemons/com.saurik.Cy@dia.Startup.plist",
  "/bin/bash",
  "/bin/sh",
  "/etc/apt",
  "/etc/ssh/sshd_config",
  "/private/var/stash",
  "/private/var/tmp/cydia.log",
  "/usr/bin/cycript",
  "/usr/bin/ssh",
  "/usr/bin/sshd",
  "/usr/libexec/sftp-server",
  "/usr/libexec/sftp-server",
  "/usr/libexec/ssh-keysign",
  "/usr/sbin/sshd",
  "/var/cache/apt",
  "/var/lib/cydia",
  "/var/log/syslog",
  "/var/tmp/cydia.log",
];

Interceptor.attach(Module.findExportByName(null, "getenv"), {
  onEnter: function (args) {
    if (args[0].isNull()) return;
    var envname = Memory.readUtf8String(args[0]);
    if (envname.indexOf("Substrate") != -1) {
      console.log("getenv: " + envname);
      stackBacktrace(this.context);
    }
  },
  onLeave: function (ret) {
    if (!ret.isNull()) {
      var s = Memory.readUtf8String(ret);
      if (s.indexOf("Substrate") != -1) {
        ret.replace(ptr("0"));
      }
    }
  },
});

Interceptor.attach(ObjC.classes.UIApplication["- canOpenURL:"].implementation, {
  onEnter: function (args) {
    var jsUrl = ObjC.Object(args[2]).toString();
    if (jsUrl.toLowerCase().indexOf("cydia://") == 0) {
      console.log("-[UIApplication canOpenURL:] >>> " + jsUrl);
      stackBacktrace(this.context);
    }
  },
});

Interceptor.attach(Module.findExportByName(null, "stat"), {
  onEnter: function (args) {
    if (args[0].isNull()) return;
    var name = Memory.readUtf8String(args[0]);

    if (
      name.indexOf("/Library/MobileSubstrate/") == 0 ||
      name == "/private/var/lib/apt" ||
      name == "/Applications/Cydia.app"
    ) {
      Memory.writeUtf8String(args[0], "/x");
      console.log("stat: " + name);
      stackBacktrace(this.context);
    }
  },
});

var jailBrokenFileExist = false;
Interceptor.attach(
  ObjC.classes.NSFileManager["- fileExistsAtPath:"].implementation,
  {
    onEnter: function (args) {
      var path = ObjC.Object(args[2]);
      var ctx = this.context;
      jailbreakPaths.forEach(function (item, i) {
        if (path == item) {
          jailBrokenFileExist = true;
          console.log("-[NSFileManager fileExistsAtPath:] " + path);
          stackBacktrace(ctx);
        }
      });
    },
    onLeave: function (retval) {
      if (this.jailBrokenFileExist) {
        retval.replace(0);
        jailBrokenFileExist = false;
      }
    },
  }
);

Interceptor.attach(
  ObjC.classes.NSFileManager["- fileExistsAtPath:isDirectory:"].implementation,
  {
    onEnter: function (args) {
      var path = ObjC.Object(args[2]);
      var ctx = this.context;
      jailbreakPaths.forEach(function (item, i) {
        if (path == item) {
          jailBrokenFileExist = true;
          console.log("-[NSFileManager fileExistsAtPath:isDirectory:] " + path);
          stackBacktrace(ctx);
        }
      });
    },
    onLeave: function (retval) {
      if (this.jailBrokenFileExist) {
        retval.replace(0);
        jailBrokenFileExist = false;
      }
    },
  }
);

Interceptor.attach(Module.findExportByName(null, "openat"), {
  onEnter: function (args) {
    if (args[1].isNull()) return;
    console.log("openat " + Memory.readUtf8String(args[1]));
  },
});

Interceptor.attach(Module.findExportByName(null, "access"), {
  onEnter: function (args) {
    if (args[0].isNull()) return;
    var pathname = Memory.readUtf8String(args[0]);
    var ctx = this.context;
    jailbreakPaths.forEach(function (item, i) {
      if (pathname == item) {
        console.log("access " + pathname);
        stackBacktrace(ctx);
      }
    });
  },
});

Interceptor.attach(Module.findExportByName(null, "faccessat"), {
  onEnter: function (args) {
    if (args[1].isNull()) return;
    var pathname = Memory.readUtf8String(args[1]);
    var ctx = this.context;
    jailbreakPaths.forEach(function (item, i) {
      if (pathname == item) {
        console.log("faccessat " + pathname);
        stackBacktrace(ctx);
      }
    });
  },
});

Interceptor.attach(Module.findExportByName(null, "fstatat"), {
  onEnter: function (args) {
    if (args[1].isNull()) return;
    var pathname = Memory.readUtf8String(args[1]);
    var ctx = this.context;
    jailbreakPaths.forEach(function (item, i) {
      if (pathname == item) {
        console.log("fstatat " + pathname);
        stackBacktrace(ctx);
      }
    });
  },
});

Interceptor.attach(Module.findExportByName(null, "open"), {
  onEnter: function (args) {
    if (args[0].isNull()) return;
    var name = Memory.readUtf8String(args[0]);
    var ctx = this.context;

    jailbreakPaths.forEach(function (item, i) {
      if (name == item) {
        console.log("open: " + item);
        stackBacktrace(ctx);
      }
    });
  },
});

Interceptor.attach(Module.findExportByName(null, "fopen"), {
  onEnter: function (args) {
    if (args[0].isNull()) return;
    var pathname = Memory.readUtf8String(args[0]);
    var ctx = this.context;

    jailbreakPaths.forEach(function (item, i) {
      if (pathname == item) {
        console.log("fopen: " + pathname);
        stackBacktrace(ctx);
      }
    });
  },
});

Interceptor.attach(Module.findExportByName(null, "fork"), {
  onEnter: function (args) {
    console.log("fork");
  },
});

Interceptor.attach(Module.findExportByName(null, "system"), {
  onEnter: function (args) {
    if (args[0].isNull()) return;
    console.log("system " + Memory.readUtf8String(args[0]));
  },
});
