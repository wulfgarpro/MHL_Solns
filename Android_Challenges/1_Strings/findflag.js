Java.perform(function() {
  let mod = Process.findModuleByName("libflag.so");
  if (mod != null) {

    // MHL{
    Memory.scan(mod.base, mod.size, "4d 48 4c 7b", {
      onMatch: function(addr) {
        console.log(`Match at: ${addr}`);
        console.log(hexdump(addr))
      },
      onComplete: function() {
        console.log("Scan complete");
      },
      onError: function(err) {
        console.log(`Scan error: ${err}`);
      }
    });
  }
});
