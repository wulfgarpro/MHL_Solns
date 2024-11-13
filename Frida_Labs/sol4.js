Java.perform(function () {
  var clz = Java.use("com.mobilehackinglab.FridaFour.Check");
  var obj = clz.$new(); // Create an instance
  console.log("Flag is: " + obj.getFlag(1337));
});
