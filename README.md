# Android GUI for [WireGuardHSM](https://github.com/mike111-droid/WireguardHSM-linux)

This is an implementation of WireGuardHSM for Android using the WireGuardGoBackend.  
This is the staging branch to prevent pollution in the main branch.

## Functionality

A big problem the previous versions have is that all PSKs are deterministic. In Version 1, the same PSK is used for the whole hour and possibly for multiple peer connections if they share the same hardware key. In Version 2, the PSK changes but is again deterministic and the same for all HWWireGuard connections with the same hardware key. A unique PSK generated from a unique parameter of the handshake is much more preferable. Such a parameter is the ephemeral key of the initiator. The inital PSK still is calucluated with initPSK = HWOperation(TIMESTAMP), but all following newPSK = HWOperation(EPH_KEY_INIT_LAST_HANDSHAKE).

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

In order to use HWWireGuard-android we need the *sc-hsm-android-library*. This library is not opensourced and only accessiable to users with a [SmartCard-HSM](https://www.smartcard-hsm.com/links.html) from CardContact Systems GmbH. Access is possiable through registering at the [CardContact Developer Network](https://www.cardcontact.de/cdn/activation.html) (CDN) and than getting access to the [GIT Repository](https://www.cardcontact.de/cdn/gitaccess.html).  
An instruction on how to use the SmartCard-HSM on Linux can be found in [WireGuardHSM-linux](https://github.com/mike111-droid/WireGuardHSM-linux).  
When we have the *sc-hsm-android-library*, we simply have to move it into the same folder as the *WireGuardHSM-android* project and hope that everything works out fine.
