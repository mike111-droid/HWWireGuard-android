# Android GUI for [WireGuardHSM](https://github.com/mike111-droid/WireguardHSM-linux)

This is an implementation of WireGuardHSM for Android using the WireGuardGoBackend.

## Building

```
$ git clone --recurse-submodules https://github.com/mike111-droid/WireGuardHSM-android
$ git clone https://github.com/mike111-droid/WireGuardHSM-androidGoBackend
$ cd WireGuardHSM-android
$ ./gradlew assembleRelease
```

## SmartCard-HSM (sc-hsm-android-library)

This library is necessary to run this program but it is not open source. 
