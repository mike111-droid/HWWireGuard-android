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

## Include the sc-hsm-android-library

In order to use WireGuardHSM-android we need the *sc-hsm-android-library*. This library is not opensourced and only accessiable to users with a [SmartCard-HSM](https://www.smartcard-hsm.com/links.html) from CardContact Systems GmbH. Access is possiable through registering at the [CardContact Developer Network](https://www.cardcontact.de/cdn/activation.html) (CDN) and than getting access to the [GIT Repository](https://www.cardcontact.de/cdn/gitaccess.html).  
An instruction on how to use the SmartCard-HSM on Linux can be found in [WireGuardHSM-linux](https://github.com/mike111-droid/WireGuardHSM-linux).  
When we have the *sc-hsm-android-library*, we simply have to move it into the same folder as the *WireGuardHSM-android* project and hope that everything works out fine.
