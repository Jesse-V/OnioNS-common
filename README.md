#OnioNS - the Onion Name System
### A New Privacy-Enhanced DNS for Tor Hidden/Onion Services

OnioNS is a privacy-enhanced, metadata-free, and highly-usable DNS for Tor onion services. Administrators can use the Onion Name System to anonymously register a meaningful and globally-unique domain name for their site. Users can then load the site just by typing "example.tor" into the Tor Browser. OnioNS is backwards-compatible with traditional .onion addresses, does not require any modifications to the Tor binary or network, and there are no central authorities in charge of the domain names. This project was specifically engineered to solve the usability problem with onion services.

This is the software implementation of the system described in "The Onion Name System: Tor-Powered Decentralized DNS for Tor Onion Services", which will appear in the 2017.1 issue of the Proceedings on Privacy Enhancing Technologies (PoPETS). It will also be demoed in July 2017 at the 17th PETS Symposium in Minneapolis.

### Repository Details [![Build Status](https://travis-ci.org/Jesse-V/OnioNS-common.svg)](https://travis-ci.org/Jesse-V/OnioNS-common)

This repository provides the common shared library for the other OnioNS packages. It is a required dependency for the HS, server, and client components. You can clone this repository using **git clone --recursive https://github.com/Jesse-V/OnioNS-common** since it uses Jesse-V/libjson-rpc-cpp, which adds support for Socks5 proxies to cinemast/libjson-rpc-cpp.

### Supported Platforms

#### Linux

**Debian, *buntu, Mint, and Fedora**

i386, amd64, and armhf architectures are supported. The software is lightweight and should run just fine on the Raspberry Pi or the BeagleBone Black.

#### Windows, OS-X, and BSD

Not currently supported. However, I will happily welcome ports of the software to OS-X and BSD and will provide upstream support. I will also welcome a Windows port of OnioNS-client and OnioNS-common. Talk to me if you are interested in helping out; we can discuss compensation.

### Installation

* **Ubuntu/Mint? Install from PPA**

The tor-onions-common package is a dependency for the other packages, so there is no need to install it manually.

* **Debian? Install from .deb file**

You can find Debian packages in [Releases section](https://github.com/Jesse-V/OnioNS-common/releases). For other architectures, see [my PPA](https://launchpad.net/~jvictors/+archive/tor-dev/+packages).

* **Otherwise, install from source**

> 1. Download and extract the latest release from the [Releases page](https://github.com/Jesse-V/OnioNS-common/releases).

> 2. Install the dependencies.

>> Debian/Ubuntu/Mint: **sudo apt-get install g++ cmake libbotan1.10-dev libcurl4-openssl-dev libargtable2-dev libmicrohttpd-dev**

>> Fedora: **yum install g++ cmake botan-devel libcurl-devel argtable-devel libmicrohttpd-devel**

Note: this software does not have a dependency on OpenSSL or use any crypto code in libcurl. You can install whichever libcurl flavor you like.

> 3. Compile and install the code.

>> **(mkdir -p build; cd build; cmake ../src) sudo make install**

You can cleanup your build with **rm -rf build src/libs/libjson-rpc-cpp/build**

### Contributing

Please file a Github issue ticket to report a bug or request a feature. Developers should use Clang 3.8 as it will compile faster and provide cleaner error messages. Feel check out the devBuild.sh and scanBuild.sh scripts as they can helpful to you. If you would like to contribute code, please fork this repo, sign your commits, and file a pull request.

I develop using Clang 3.8 on Debian Testing amd64.
