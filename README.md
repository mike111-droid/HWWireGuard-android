# Android GUI for [WireGuardHSM](https://github.com/mike111-droid/WireguardHSM-linux)

This is an implementation of WireGuardHSM for Android using the WireGuardGoBackend.  
This is the staging branch to prevent pollution in the main branch.

## Building

```
$ git clone --recurse-submodules https://github.com/mike111-droid/WireGuardHSM-android
$ git clone https://github.com/mike111-droid/WireGuardHSM-androidGoBackend
$ cd WireGuardHSM-android
$ ./gradlew assembleRelease
```
