# Android GUI for [WireGuardHSM](https://github.com/mike111-droid/WireguardHSM-linux)

This is an implementation of WireGuardHSM for Android using the WireGuardGoBackend.  
This is the staging branch to prevent pollution in the main branch.

## Functionality
The first version of HWWireGuard is also the most fundamental and straightforward to design. The idea is to use either the SmartCard-HSM or Android KeyStores to generate a PSK. By doing this, the PSK depends on a secret from a hardware device, and an attacker can only calculate it by either extracting the key or stealing the devices and forging the authentication. The calculated PSK needs to be the same for both communication peers.

## Structure
HWWireGuard is an extension of the existing WireGuard and, as such, additional code changes need to be marked. The main new classes are in the *ui* package in the subfolder *hwwireguard*. Other changes that are necessary in the code iteself sould be marked by the tags:  
/\* Custom change begin \*/  
*\/\/ Additional Code*  
/\* Custom change end \*/  

## Building

```
$ git clone --recurse-submodules https://github.com/mike111-droid/HWWireGuard-android
$ git clone https://github.com/mike111-droid/HWWireGuard-androidGoBackendmod
$ cd WireGuardHSM-android
$ ./gradlew assembleRelease
```

## Include the sc-hsm-android-library

In order to use WireGuardHSM-android we need the *sc-hsm-android-library*. This library is not opensourced and only accessiable to users with a [SmartCard-HSM](https://www.smartcard-hsm.com/links.html) from CardContact Systems GmbH. Access is possiable through registering at the [CardContact Developer Network](https://www.cardcontact.de/cdn/activation.html) (CDN) and than getting access to the [GIT Repository](https://www.cardcontact.de/cdn/gitaccess.html).  
An instruction on how to use the SmartCard-HSM on Linux can be found in [WireGuardHSM-linux](https://github.com/mike111-droid/WireGuardHSM-linux).  
When we have the *sc-hsm-android-library*, we simply have to move it into the same folder as the *WireGuardHSM-android* project and hope that everything works out fine.
