var flagFn = Module.enumerateExports("libFridaNine.so")[0]["address"];

Interceptor.attach(flagFn, {
  onEnter: function (args) {},
  onLeave: function (retval) {
    console.log("Original return val: " + retval);
    retval.replace(623); // Change return value to 623.
  },
});
