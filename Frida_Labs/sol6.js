Java.performNow(function () {
  Java.choose("com.mobilehackinglab.FridaSix.MainActivity", {
    // use the instance
    onMatch: function (instance) {
      var Checker = Java.use("com.mobilehackinglab.FridaSix.Checker");
      var checker = Checker.$new();
      checker.x.value = 1337;
      checker.y.value = 1200;
      instance.getFlag(checker);
    },
    onComplete: function () {},
  });
});
