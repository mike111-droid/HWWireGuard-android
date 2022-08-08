# Android GUI for [WireGuardHSM](https://github.com/mike111-droid/WireguardHSM-linux)/HWWireGuard

This is an implementation of WireGuardHSM/HWWireGuard for Android using the WireGuardGoBackend. The different implemented versions are in different branches.

1. **staging_v1**: This is the simplest HWWireGuard version with a deterministic PSK for the whole hour.
2. **staging_v2_1**: Here the initial PSK is generated with hardware operation. Afterwards PSKs change with every handshake (every 2 minutes) using SHA256.
3. **staging_v2_2**: Here the initial PSK is generated with hardware operation. Afterwards PSKs change with every handshake (every 2 minutes) using hardware operation.
4. **staging_v3_final**: Here the initial PSK generated with deterministic TIMESTAMP input using hardware operation. Afterwards PSKs change with every handshake using the ephemeral key of the initiator as input for the hardware operation.

Each branch discribes the actual implementation in more detail.

## Structure
The main new classes are in the *ui* package in the subfolder *hwwireguard*. Other changes that are necessary in the code iteself sould be marked by the tags:  
/\* Custom change begin \*/  
*\/\/ Additional Code*  
/\* Custom change end \*/  

## Building

```
$ git clone --recurse-submodules https://github.com/mike111-droid/HWWireGuard-android
$ git clone https://github.com/mike111-droid/WireGuardHSM-androidGoBackendmod
$ cd WireGuardHSM-android
$ ./gradlew assembleRelease
```

## Include the sc-hsm-android-library

In order to use WireGuardHSM-android we need the *sc-hsm-android-library*. This library is not opensourced and only accessiable to users with a [SmartCard-HSM](https://www.smartcard-hsm.com/links.html) from CardContact Systems GmbH. Access is possiable through registering at the [CardContact Developer Network](https://www.cardcontact.de/cdn/activation.html) (CDN) and than getting access to the [GIT Repository](https://www.cardcontact.de/cdn/gitaccess.html).  
An instruction on how to use the SmartCard-HSM on Linux can be found in [WireGuardHSM-linux](https://github.com/mike111-droid/WireGuardHSM-linux).  
When we have the *sc-hsm-android-library*, we simply have to move it into the same folder as the *WireGuardHSM-android* project and hope that everything works out fine.
