# Android GUI for [WireGuardHSM](https://github.com/mike111-droid/WireguardHSM-linux)

This is an implementation of WireGuardHSM for Android using the WireGuardGoBackend.  
This is the staging branch to prevent pollution in the main branch.

## Functionality

Version 2.2 improves by changing the PSK with every successful handshake by calculating newPSK = HWOperation(oldPSK), where HWOperation is a hardware-backed operation with either Android KeyStores or the SmartCard-HSM. This changes the PSK every two minutes and increase the frequency of PSK-changes. As a result, a stolen PSK can only be used for smaller time frames.



## Structure
HWWireGuard is an extension of the existing WireGuard and, as such, additional code changes need to be marked. The main new classes are in the *ui* package in the subfolder *hwwireguard*. Other changes that are necessary in the code iteself sould be marked by the tags:  
/\* Custom change begin \*/  
*\/\/ Additional Code*  
/\* Custom change end \*/  

## Building

```
$ git clone --recurse-submodules https://github.com/mike111-droid/HWWireGuard-android
$ git clone https://github.com/mike111-droid/HWWireGuard-androidGoBackend
$ cd WireGuardHSM-android
$ ./gradlew assembleRelease
```

## Include the sc-hsm-android-library

In order to use WireGuardHSM-android we need the *sc-hsm-android-library*. This library is not opensourced and only accessiable to users with a [SmartCard-HSM](https://www.smartcard-hsm.com/links.html) from CardContact Systems GmbH. Access is possiable through registering at the [CardContact Developer Network](https://www.cardcontact.de/cdn/activation.html) (CDN) and than getting access to the [GIT Repository](https://www.cardcontact.de/cdn/gitaccess.html).  
An instruction on how to use the SmartCard-HSM on Linux can be found in [WireGuardHSM-linux](https://github.com/mike111-droid/WireGuardHSM-linux).  
When we have the *sc-hsm-android-library*, we simply have to move it into the same folder as the *WireGuardHSM-android* project and hope that everything works out fine.
