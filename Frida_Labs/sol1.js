Java.perform(function () {
  var clz = Java.use("com.mobilehackinglab.fridaone.MainActivity");
  clz.generateRandomNumber.implementation = function () {
    var rnd = this.generateRandomNumber();
    console.log("Random number is " + rnd);
    return rnd;
  };
});
