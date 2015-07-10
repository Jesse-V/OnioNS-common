#OnioNS - the Onion Name System
### Tor-Powered Distributed DNS for Tor Hidden Services

The Onion Name System (OnioNS) is a privacy-enhanced, distributed, and highly usable DNS for Tor hidden services. It allows users to reference a hidden service by a meaningful globally-unique domain name chosen by the hidden service operator. The system is powered by the Tor network and relies on a distributed database. This project aims to address the major usability issue that has been with Tor hidden services since their introduction in 2002. The official project page is onions55e7yam27n.onion, which is example.tor under OnioNS.

### Repository Details

This repository provides the common core code and acts as a dependency for the other OnioNS packages. Please see the -HS, -server, and -client repositories for more information.

### Supported Systems

#### Linux

**Ubuntu 14.04+, Debian 8+, Linux Mint 17+, Fedora 21+**

i386, amd64, and armhf architectures are supported, so it should run on most 32-bit, 64-bit, and ARM machines. If you have an ARM board (Pi, BBB, Odroid, etc) feel free to test it.

#### Windows

Not currently supported. I have long-term plans of porting this repository and OnioNS-client to Windows, but no intentions to port the other packages to Windows.

#### OS-X and *BSD

Not currently supported, support planned in the far future. I am willing to provide upstream support to anyone who wishes to port the software over there. I have not attempted to compile this code on any BSD system. My current primary focus is developing the Linux edition.

### Installation

* **Install from PPA**

The tor-onions-common package is a dependency for the other packages, so it will automatically install.

* **Install from .deb file**

I provide amd64 .deb builds in the [Releases section](https://github.com/Jesse-V/OnioNS/releases), which should work for you. For other architectures, you may download from [my PPA](https://launchpad.net/~jvictors/+archive/tor-dev/+packages).

* **Install from source**

> 1. Download the latest .zip or .tar.gz archive from the Releases page and unzip it.
> 2. Debian/Ubuntu/Mint: **sudo apt-get install g++ cmake botan1.10-dev libasio-dev libboost-system-dev** Fedora: **yum install g++ cmake botan-devel asio-devel boost-system**
> 3. **./build.sh**
> 4. **cd build/**
> 5. **sudo make install**

The ClangBuild.sh script is available if you prefer the Clang compiler. This script is recommended if you are developing or hacking OnioNS. You will need to install *clang-format-3.6* before running that as ClangBuild.sh will also re-style your code to the official development style, which is based on Chromium.
