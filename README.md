# Android GUI for [WireGuardHSM](https://github.com/mike111-droid/WireguardHSM-linux)/HWWireGuard

This is an implementation of WireGuardHSM/HWWireGuard for Android using the WireGuardGoBackend. The different implemented versions are in different branches.

1. *staging_v1*: This is the simplest HWWireGuard version with a deterministic PSK for the whole hour.
2. *staging_v2_1*: Here the initial PSK is generated with hardware operation. Afterwards PSKs change with every handshake (every 2 minutes) using SHA256.
3. *staging_v2_2*: Here the initial PSK is generated with hardware operation. Afterwards PSKs change with every handshake (every 2 minutes) using hardware operation.
4. *staging_v3_final*: Here the initial PSK generated with deterministic TIMESTAMP input using hardware operation. Afterwards PSKs change with every handshake using the ephemeral key of the initiator as input for the hardware operation.

Each branch discribes the actual implementation in more detail.

## Building

```
$ git clone --recurse-submodules https://github.com/mike111-droid/WireGuardHSM-android
$ git clone https://github.com/mike111-droid/WireGuardHSM-androidGoBackendmod
$ cd WireGuardHSM-android
$ ./gradlew assembleRelease
```

## SmartCard-HSM (sc-hsm-android-library)

This library is necessary to run this program but it is not open source. 
