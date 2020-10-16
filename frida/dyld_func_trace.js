function stackBacktrace(ctx) {
  console.log(
    "\tBacktrace:\n\t" +
      Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .join("\n\t")
  );
}

// Interceptor.attach(Module.findExportByName(null, "getsectbynamefromheader_64"), {
//   onEnter: function (args) {
//     console.log(
//       "getsectbynamefromheader_64 " +
//         "segment name: " + args[1].readUtf8String() + ", " +
//         "section name" + args[2].readUtf8String()
//     );
//     stackBacktrace(this.context);
//   },
// });

Interceptor.attach(Module.findExportByName(null, "getsectiondata"), {
  onEnter: function (args) {
    console.log(
      "getsectiondata " +
        "segment name: " + args[1].readUtf8String() + ", " +
        "section name" + args[2].readUtf8String()
    );
    // stackBacktrace(this.context);
  },
});

/*
uint32_t _dyld_image_count(void);

returns the current number of images mapped in by dyld. Note that using this count to iterate all images is not thread safe, because another thread may be adding or removing images during the iteration.
*/
Interceptor.attach(Module.findExportByName(null, "_dyld_image_count"), {
  onEnter: function (args) {
    console.log("dyld_image_count");
    stackBacktrace(this.context);
  },
});

/*
const char* _dyld_get_image_name(uint32_t image_index);

returns the name of the image indexed by image_index. The C-string continues to be owned by dyld and should not deleted. If image_index is out of range NULL is returned.
*/
Interceptor.attach(Module.findExportByName(null, "_dyld_get_image_name"), {
  onEnter: function (args) {
    // args[0] = ptr("0");
    // console.log("_dyld_get_image_name " + args[0]);
  },
  onLeave: function (retval) {
    var name = Memory.readUtf8String(retval);
    if (
      name.startsWith("/System/Library/") ||
      name.startsWith("/usr/lib/system/") ||
      (name.startsWith("/usr/lib/") && name.toLowerCase().indexOf("substrate") == -1)
    ) {
      // /usr/lib/substrate/SubstrateLoader.dylib
      // /usr/lib/substrate/SubstrateInserter.dylib
      // /usr/lib/libsubstrate.dylib
      return;
    }
    console.log("_dyld_get_image_name " + name);
    stackBacktrace(this.context);
  },
});

/*
const struct mach_header* _dyld_get_image_header(uint32_t image_index);

returns a pointer to the mach header of the image indexed by image_index.  If image_index isout of range, NULL is returned.
*/
Interceptor.attach(Module.findExportByName(null, "_dyld_get_image_header"), {
  onEnter: function (args) {
    console.log("dyld_get_image_header:");
    stackBacktrace(this.context);
  },
});

/*
intptr_t _dyld_get_image_vmaddr_slide(uint32_t image_index);

returns the virtural memory address slide amount of the image indexed by image_index. 
*/
Interceptor.attach(
  Module.findExportByName(null, "_dyld_get_image_vmaddr_slide"),
  {
    onEnter: function (args) {
      console.log("_dyld_get_image_vmaddr_slide");
      stackBacktrace(this.context);
    },
  }
);

/*
void _dyld_register_func_for_add_image(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide));

registers the specified function to be called when a new image is added (a bundle or a dynamic shared library) to the program. When this function is first registered it is called for once for each image that is currently part of the process.
*/
Interceptor.attach(
  Module.findExportByName(null, "_dyld_register_func_for_add_image"),
  {
    onEnter: function (args) {
      console.log("_dyld_register_func_for_add_image");
      stackBacktrace(this.context);
    },
  }
);

/*
int dladdr(const void* addr, Dl_info* info);

The dladdr() function queries dyld (the dynamic linker) for information about the image containing the address addr.  The information is returned in the structure specified by info.  

typedef struct dl_info {
    const char      *dli_fname;     //Pathname of shared object
    void            *dli_fbase;     //Base address of shared object
    const char      *dli_sname;     //Name of nearest symbol
    void            *dli_saddr;     //Address of nearest symbol
} Dl_info;
*/
 Interceptor.attach(Module.findExportByName(null, "dladdr"), {
  info: null,
  onEnter: function (args) {
    this.info = args[1];
  },
  onLeave: function (ret) {
    if (this.info.isNull()) return;
    var dli_fname = Memory.readPointer(this.info);
    var dli_sname = Memory.readPointer(this.info.add(Process.pointerSize * 2));

    var js_fname = Memory.readUtf8String(dli_fname);
    var js_sname = Memory.readUtf8String(dli_sname);

    if (
      js_fname.startsWith("/Library/MobileSubstrate/DynamicLibraries") ||
      js_fname.indexOf(".app/Frameworks/") != -1
    ) {
      console.log("dladdr " + js_fname + " " + js_sname);
      stackBacktrace(this.context);
    }
  },
});

/*
bool dlopen_preflight(const char* path);

* preflight the load of a dynamic library or bundle
* dlopen_preflight() uses the same steps as dlopen() to find a compatible mach-o file.
*/
Interceptor.attach(Module.findExportByName(null, "dlopen_preflight"), {
  onEnter: function (args) {
    if (args[0].isNull()) return;
    console.log("dlopen_preflight " + Memory.readUtf8String(args[0]));
    stackBacktrace(this.context);
  },
});

/*
void *dlopen(const char *filename, int flag);

load and link a dynamic library or bundle
*/
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
  onEnter: function (args) {
    if (args[0].isNull()) {
      return;
    }
    var filename = Memory.readUtf8String(args[0]);
    if (
      filename.startsWith("/System/Library/") ||
      filename.startsWith("/usr/lib/system/") ||
      (filename.startsWith("/usr/lib/") && filename.toLowerCase().indexOf("substrate") == -1)
    ) {
      // /usr/lib/substrate/SubstrateLoader.dylib, /usr/lib/substrate/SubstrateInserter.dylib, /usr/lib/libsubstrate.dylib
      return;
    }
    console.log("dlopen " + filename);
    stackBacktrace(this.context);
  },
});

/*
void *dlsym(void *handle, const char *symbol);
*/
Interceptor.attach(Module.findExportByName(null, "dlsym"), {
  onEnter: function (args) {
    if (args[1].isNull()) return;
    console.log("dlsym " + Memory.readUtf8String(args[1]));
    stackBacktrace(this.context);
  },
});
