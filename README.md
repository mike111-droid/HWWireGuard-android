# Android GUI for [WireGuardHSM](https://github.com/mike111-droid/WireguardHSM-linux)/HWWireGuard

This is an implementation of WireGuardHSM/HWWireGuard for Android using the WireGuardGoBackend. The different implemented versions are in different branches.

1. *staging_v1*: This is the simplest HWWireGuard version and sets the PSK hourly.
2. *staging_v2_1*: This is the simplest HWWireGuard version and sets the PSK hourly.

## Building

```
$ git clone --recurse-submodules https://github.com/mike111-droid/WireGuardHSM-android
$ git clone https://github.com/mike111-droid/WireGuardHSM-androidGoBackendmod
$ cd WireGuardHSM-android
$ ./gradlew assembleRelease
```

## SmartCard-HSM (sc-hsm-android-library)

This library is necessary to run this program but it is not open source. 
