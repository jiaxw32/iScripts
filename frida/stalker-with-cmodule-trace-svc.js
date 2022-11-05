const cm = new CModule(`
#include <gum/gumstalker.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void on_message(const gchar *message);
static void log(const gchar *format, ...);
static void on_arm64_before(GumCpuContext *cpu_context, gpointer user_data);


static void
log(const gchar *format, ...)
{
    gchar *message;
    va_list args;

    va_start(args, format);
    message = g_strdup_vprintf(format, args);
    va_end(args);

    on_message(message);
    g_free(message);
}


// typedef void * gpointer;
void transform(GumStalkerIterator *iterator,
               GumStalkerOutput *output,
               gpointer user_data)
{
    cs_insn *insn;

    gpointer base = *(gpointer*)user_data;
    gpointer end = *(gpointer*)(user_data + sizeof(gpointer));
    gpointer slide = *(gpointer*)(user_data + sizeof(gpointer) * 2);
    
    while (gum_stalker_iterator_next(iterator, &insn))
    {
        gboolean in_target = (gpointer)insn->address >= base && (gpointer)insn->address < end;
        if(in_target)
        {
            guint64 offset = insn->address - (guint64)slide;
            if(strcmp(insn->mnemonic, "svc") == 0){
                log("%#llx-%p\t%s %s", offset, (gpointer)insn->address, insn->mnemonic, insn->op_str);
                gum_stalker_iterator_put_callout(iterator, on_arm64_before, user_data, NULL);
            } 
            else {
                log("%#llx-%p\t%s %s", offset, (gpointer)insn->address, insn->mnemonic, insn->op_str);
            }
        }
        gum_stalker_iterator_keep(iterator);
    }
}


static void
on_arm64_before(GumCpuContext *cpu_context,
        gpointer user_data)
{
    gpointer slide = *(gpointer*)(user_data + sizeof(gpointer) * 2);
    guint64 offset = (guint64)cpu_context->pc - (guint64)slide;
    
    int syscall_num = cpu_context->x[16];
    if(syscall_num == 338){ // stat64 syscall
        const char *path = (const char *)cpu_context->x[0];
        log(">>> offset: %#llx, syscall number: %d, path: %s", offset, syscall_num, path);
    } else {
        log(">>> offset: %#llx, syscall number: %d", offset, syscall_num);
    }
}`, {
    on_message: new NativeCallback(messagePtr => {
        const message = messagePtr.readUtf8String();
        console.log(message)
        // send(message)
      }, 'void', ['pointer']),
});

const appImage = Process.enumerateModulesSync()[0];
var startAddr = appImage.base;
var endAddr = startAddr.add(appImage.size);
console.log("image name: " + appImage.name + ", image size: " + appImage.size);
console.log('start address: ' + startAddr + ', end address: ' + endAddr);

var addr = Module.findExportByName("libSystem.B.dylib", "_dyld_get_image_vmaddr_slide");
var _dyld_get_image_vmaddr_slide = new NativeFunction(addr, "long", ["uint"]);
var slide = _dyld_get_image_vmaddr_slide(0);
console.log("slide: 0x" + slide.toString(16));

const userData = Memory.alloc(Process.pointerSize * 5);
userData.writePointer(startAddr)
userData.add(Process.pointerSize).writePointer(endAddr);
userData.add(Process.pointerSize * 2).writePointer(ptr(slide));

// const array = [0x82F3C0, 0x82F818, 0x82f500, 0x82FA1C];
const array = [0x82f500];

array.forEach(addr => {
    var targetAddr = startAddr.add(ptr(addr)); 
    console.log("trace target address: " + targetAddr);

    Interceptor.attach(targetAddr, {
        onEnter: function(args) {
            console.log('ThreadId : ' + this.threadId + ", Return: " + this.returnAddress);

            Stalker.follow(this.threadId, {
                transform: cm.transform,
                data: userData,
            });
        },
        onLeave(retval) {
            Stalker.unfollow(this.threadId);
            Stalker.garbageCollect();
            console.log("trace finished.");
        }
    });
});



/*
const mainThread = Process.enumerateThreads()[0];
Stalker.follow(mainThread.id, {
    
    transform: cm.transform,
    data: userData
});

*/