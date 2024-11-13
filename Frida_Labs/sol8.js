var strCmpAddr = Module.getExportByName("libc.so", "strcmp");

Interceptor.attach(strCmpAddr, {
  onEnter: function (args) {
    var arg0 = Memory.readUtf8String(args[0]);
    var arg1 = Memory.readUtf8String(args[1]);
    if (arg0.includes("Hello")) {
      // filter on our string so we know which `strcmp` is ours
      console.log("The flag is: " + arg1);
    }
  },
  onLeave: function (retval) {},
});
