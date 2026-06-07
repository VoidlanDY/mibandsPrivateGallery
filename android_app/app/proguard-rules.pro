# ProGuard rules for PrivateGalleryCompanion

# Keep ADB process execution
-keepclassmembers class java.lang.ProcessBuilder {
    *;
}

# Keep SHA-256
-keep class java.security.MessageDigest {
    *;
}

# Keep activity
-keep class com.privategallery.MainActivity {
    *;
}
