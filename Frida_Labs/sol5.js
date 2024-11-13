Java.perform(function () {
  Java.choose("com.mobilehackinglab.FridaFive.MainActivity", {
    onMatch: function (instance) {
      // the MainActivity instance
      console.log("Found instance");
      instance.flag(1337); // call an instance's function
    },
    onComplete: function () {},
  });
});
