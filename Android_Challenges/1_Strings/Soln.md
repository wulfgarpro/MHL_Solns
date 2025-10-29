# Soln

Two key hints from the challenge description are:

- Understand the code and find a method to invoke the exported activity.
- Utilize Frida for tracing or employ Frida's memory scanning.

Looking at `AndroidManifest.xml`, there's two exported activities: `MainActivity` and `Activity2`.

They're explicitly exported with `android:exported="true"` (as opposed to implicitly with a
defined `<intent-filter>`).

The relevant MASTG: <https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0029/>.

`Activity2` is declared as:

```xml
<activity
  android:exported="true"
  android:name="com.mobilehackinglab.challenge.Activity2">
  <intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data
      android:host="labs"
      android:scheme="mhl"/>
  </intent-filter>
</activity>
```

There's no other references to `Activity2` in the codebase.

We can launch it ourselves using Android's Activity Manager `am`:

```shell
am start -n com.mobilehackinglab.challenge/.Activity2 -a "android.intent.action.VIEW" \
  -c "android.intent.category.DEFAULT" -d "mhl://labs"
```

- `-n` is component name
- `-a` is action
- `-c` is category
- `-d` is data

But when we launch it, it immediately closes.

Looking at `Activity2`'s `onCreate` method:

```java
@Override  // androidx.fragment.app.FragmentActivity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.setContentView(layout.activity_2);
        String s = this.getSharedPreferences("DAD4", 0).getString("UUU0133", null);
        if(Intrinsics.areEqual(this.getIntent().getAction(), "android.intent.action.VIEW") && Intrinsics.areEqual(s, this.cd())) {
            Uri uri0 = this.getIntent().getData();
            if(uri0 != null && Intrinsics.areEqual(uri0.getScheme(), "mhl") && Intrinsics.areEqual(uri0.getHost(), "labs")) {
                byte[] arr_b = Base64.decode(uri0.getLastPathSegment(), 0);
                if(arr_b != null) {
                    byte[] arr_b1 = "your_secret_key_1234567890123456".getBytes(Charsets.UTF_8);
                    Intrinsics.checkNotNullExpressionValue(arr_b1, "this as java.lang.String).getBytes(charset)");
                    if(this.decrypt("AES/CBC/PKCS5Padding", "bqGrDKdQ8zo26HflRsGvVA==", new SecretKeySpec(arr_b1, "AES")).equals(new String(arr_b, Charsets.UTF_8))) {
                        System.loadLibrary("flag");
                        String s1 = this.getflag();
                        Toast.makeText(this.getApplicationContext(), s1, 1).show();
                        return;
                    }

                    this.finishAffinity();
                    this.finish();
                    System.exit(0);
                    return;
                }

                this.finishAffinity();
                this.finish();
                System.exit(0);
                return;
            }

            this.finishAffinity();
            this.finish();
            System.exit(0);
            return;
        }

        this.finishAffinity();
        this.finish();
        System.exit(0);
    }
```

It's obvious we're hitting one of the exit conditions.

Analysing the alternative code path, there are some conditions we have to meet:

- `String s = this.getSharedPreferences("DAD4", 0).getString("UUU0133", null);` - the app's shared
  preferences has to include a shared preferences file `"DAD4"` with key `UUU0133`.
- `this.getIntent().getAction(), "android.intent.action.VIEW")` - the intent action that launched
  the activity must be `android.intent.action.VIEW` (we already met this condition in the above `am`
  command).
- `Intrinsics.areEqual(s, this.cd())` - the value of the `"UUU0133"` key in the shared preferences
  must be equal to the result of `this.cd()`.

Looking in `/data/data/com.mobilehackinglab.challenge/shared_prefs/`, there's no shared preferences
file.

Searching the decompiled code for `"UUU0133"`, we find another function, this time in `MainActivity`
that creates the shared preferences file with the required key - `KLOW`:

```java
public final void KLOW() {
    SharedPreferences.Editor sharedPreferences$Editor0 = this.getSharedPreferences("DAD4", 0).edit();
    Intrinsics.checkNotNullExpressionValue(sharedPreferences$Editor0, "edit(...)");
    sharedPreferences$Editor0.putString("UUU0133", new SimpleDateFormat("dd/MM/yyyy", Locale.getDefault()).format(new Date()));
    sharedPreferences$Editor0.apply();
}
```

But `KLOW` is never called. So, we'll need to call it ourselves to create the requisite shared
preferences using a Frida script:

```js
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
```

Launch the app, inject the script, and call `KLOW` as follows:

```sh
$ frida -U -l script.js -f com.mobilehackinglab.challenge
[SM S926B::com.mobilehackinglab.challenge ]-> KLOW()
Instance of MainActivity Found
Calling Klow...
Check for /data/data/com.mobilehackinglab.challenge/shared_prefs/DAD4.xml
```

In the above code we search for an existing instance of the `MainActivity` with `Java.choose()`, so
that it's correctly wired to Android's lifecycle management. See <https://e1mazahy.gitbook.io/droidtomesec/android-pentesting/frida/calling-methods#invoking-methods-on-an-existing-instance> for more information.

The `"DAD4.xml"` shared preferences file is created with the contents:

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="UUU0133">29/10/2025</string>
</map>
```

That's just today's date in `dd/MM/yyyy` format.

So what is the result of `this.cd()` that we must match?

```java
private final String cd() {
    String s = new SimpleDateFormat("dd/MM/yyyy", Locale.getDefault()).format(new Date());
    Intrinsics.checkNotNullExpressionValue(s, "format(...)");
    Activity2Kt.cu_d = s;
    String s1 = Activity2Kt.cu_d;
    if(s1 == null) {
        Intrinsics.throwUninitializedPropertyAccessException("cu_d");
        return null;
    }

    return s1;
}
```

Today's date in `dd/MM/yyyy` format. So, we've now done that!

Following the initial conditions, there is some logic dealing with the intent data:

```java
Uri uri0 = this.getIntent().getData();
if(uri0 != null && Intrinsics.areEqual(uri0.getScheme(), "mhl") && Intrinsics.areEqual(uri0.getHost(), "labs")) {
    byte[] arr_b = Base64.decode(uri0.getLastPathSegment(), 0);
    if(arr_b != null) {
        byte[] arr_b1 = "your_secret_key_1234567890123456".getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(arr_b1, "this as java.lang.String).getBytes(charset)");
        if(this.decrypt("AES/CBC/PKCS5Padding", "bqGrDKdQ8zo26HflRsGvVA==", new SecretKeySpec(arr_b1, "AES")).equals(new String(arr_b, Charsets.UTF_8))) {
            System.loadLibrary("flag");
            String s1 = this.getflag();
            Toast.makeText(this.getApplicationContext(), s1, 1).show();
            return;
        }
      ...
    }
  ...
}
```

In summary, the intent data is cast to a URI, and the scheme + host are validated as `mhl` and
`labs` respectively. To pass the data as a URI to the intent, we specifically designate
`-d mhl://labs` as demonstrated in the `am` command above. Next the last path segment is decoded as
Base 64, indicating that we have to supply an additional data element that's Base 64 encoded after
the host designation. This data element is compared with the AES decrypted result via
`self.decrypt()` of `"bqGrDKdQ8zo26HflRsGvVA=="`, using `"your_secret_key_1234567890123456"` as the
key. If they match, the native library `libflag.so` is loaded using `System.loadLibrary` and `s1` is
set to the result of `getFlag()`: `String s1 = this.getflag();`.

So, what does `self.decypt()` do? What value must the last path segment hold?

Here's `self.decrypt()`:

```java
public final String decrypt(String algorithm, String cipherText, SecretKeySpec key) {
    Intrinsics.checkNotNullParameter(algorithm, "algorithm");
    Intrinsics.checkNotNullParameter(cipherText, "cipherText");
    Intrinsics.checkNotNullParameter(key, "key");
    Cipher cipher0 = Cipher.getInstance(algorithm);
    try {
        byte[] arr_b = "1234567890123456".getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(arr_b, "this as java.lang.String).getBytes(charset)");
        cipher0.init(2, key, new IvParameterSpec(arr_b));
        byte[] arr_b1 = cipher0.doFinal(Base64.decode(cipherText, 0));
        Intrinsics.checkNotNull(arr_b1);
        return new String(arr_b1, Charsets.UTF_8);
    }
    catch(Exception e) {
        throw new RuntimeException("Decryption failed", e);
    }
}
```

At the call site, the algorithm is AES, the cipher text is the above Base 64 encoded string, and
the key is a secret key derived using `your_secret_key_1234567890123456`. Of note here is the
initialization vector value `1234567890123456`.

With all of these elements, we can decrypt the Base 64 encoded cipher text using CyberChef.

In CyberChef, we pass `bqGrDKdQ8zo26HflRsGvVA==` to: **From Base64** -> **AES Decrypt**, using:

- **Key**=your_secret_key_1234567890123456
- **IV**=1234567890123456
- **Mode**=CBC
- **Input**=Raw
- **Output**=Raw

This reveals: `mhl_secret_1337`. But since the input is Base 64 decoded, we have to Base 64 encode
it before supplying it as the last path segment (just add it into the CyberChef pipeline).

With that done, we can update the `am` command as follows:

```shell
am start -n com.mobilehackinglab.challenge/.Activity2 -a "android.intent.action.VIEW" \
  -c "android.intent.category.DEFAULT" -d "mhl://labs//bWhsX3NlY3JldF8xMzM3"
```

Next `Toast.makeText(...)` is called - according to
<https://developer.android.com/guide/topics/ui/notifiers/toasts>, it triggers a small popup with a
message.

When we run that command, we see the activity launch and display "Success".

Without going into too much detail, the `libflag.so` library function `getflag();` returns the
string `"Success"`, per the Ghidra decompilation:

```c
_JNIEnv::NewStringUTF(param_1,"Success");
```

So where is the flag?

The original instructions mentioned:

- Utilize Frida for tracing or employ Frida's memory scanning.

And so (presumably) `getflag();` also de-obfuscates a flag and puts it into memory for us to read.

So, we have to find the value of the flag in memory using Frida.

We write another Frida script to scan memory for a string containing the flag format `MHL{`:

```js
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
```

And run it like so:

```sh
frida -l findflag.js -n Strings -U
```

The above `-n` will attach to the previously running `Strings` app where the flag has been read
into memory.

Resulting in:

```sh
Scan complete
Match at: 0x7645c0c05c
             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
7645c0c05c  4d 48 4c 7b 49 4e 5f 54 48 45 5f 4d 45 4d 4f 52  MHL{IN_THE_MEMOR
7645c0c06c  59 7d 00 00 00 00 00 00 00 00 00 00 00 00 00 00  Y}..............
```
