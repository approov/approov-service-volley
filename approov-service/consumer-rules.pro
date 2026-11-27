# Keep Approov SDK public interfaces
-keep class com.criticalblue.approovsdk.** { *; }

# Tink is bundled relocated under io.approov.util.volley and is otherwise left
# for R8 to shrink: no rule keeps its classes. This is Tink's own
# META-INF/proguard/protobuf.pro restated for the relocated package. It only
# keeps fields of protobuf messages that are already live.
-keepclassmembers class * extends io.approov.util.volley.tink.shaded.protobuf.GeneratedMessageLite {
  <fields>;
}

# Ensure native methods and JNI bindings are preserved
-keepclasseswithmembernames class * {
    native <methods>;
}
