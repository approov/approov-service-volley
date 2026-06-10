# Keep Approov SDK public interfaces
-keep class com.criticalblue.approovsdk.** { *; }

# Keep BouncyCastle relocated ASN.1 classes
-keep class io.approov.internal.volley.bouncycastle.** { *; }

# Ensure native methods and JNI bindings are preserved
-keepclasseswithmembernames class * {
    native <methods>;
}

-keepclasseswithmembernames class * {
    public <init>(java.lang.String, int);
}
