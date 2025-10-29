function KLOW() {
Java.perform(function () {
    Java.choose("com.mobilehackinglab.challenge.MainActivity" , {
      onMatch : function(instance){
        console.log("Instance of MainActivity Found");
        console.log("Calling Klow...");
        instance.KLOW();
        console.log("Check for /data/data/com.mobilehackinglab.challenge/shared_prefs/DAD4.xml");
      },
      onComplete:function(){}
    });
});
}

