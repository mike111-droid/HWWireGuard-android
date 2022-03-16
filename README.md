# Android GUI for [WireGuardHSM](https://github.com/mike111-droid/WireguardHSM-linux)

This is an implementation of WireGuardHSM for Android using the WireGuardGoBackend.  
This is the sc-hsm-library-include branch which serves as a backup point (from when the sc-hsm-android-library was successfully included) in case the staging branches gets broken.

## Building

```
$ git clone --recurse-submodules https://github.com/mike111-droid/WireGuardHSM-android
$ git clone https://github.com/mike111-droid/WireGuardHSM-androidGoBackend
$ cd WireGuardHSM-android
$ ./gradlew assembleRelease
```





