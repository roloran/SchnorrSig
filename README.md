# SchnorrSig

Schnorr signatures for Arduino and PlatformIO projects.

This library was developed to have a public/private-key signature system with very short signatures.
It has only been been tested on an ESP32S3.

## Installation: Arduino

Download the repository as .zip file and include it in the Arduino IDE via `Sketch` -> `Include Library` -> `Add .ZIP Library`.
Alternatively clone the repository to the `libraries` folder.

## Installation: PlatformIO

Add the library to the `platformio.ini`:

```
lib_deps = https://github.com/roloran/SchnorrSig
```

## Usage

An example showing all parts of key generation, signing and verifying is present in the `examples` folder.

The general workflow is:
- Create a `SchnorrSigCtx` context. This context is needed for handling keys.
- For each private key create a `SchnorrSigSign` object to sign messages with that key.
- For each public key create a `SchnorrSigVerify` object to verify signatures signed with the corresponding private key.

The Python file in the `examples` folder shows how a backend can verify messages sent by an device and generate signed messages, that can be verified on the device.

## Security Warning

Building one's own crypto is generally a bad idea. There is no reason to hope this is safe to use.

## LICENSE

The code is published using the Apache-2.0 license.
