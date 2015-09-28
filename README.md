#OnioNS - the Onion Name System
### Tor-Powered Distributed DNS for Tor Hidden Services

OnioNS is a distributed, privacy-enhanced, metadata-free, and highly usable DNS for Tor hidden services. OnioNS allows hidden service operators to select a meaningful and globally-unique domain name for their service, which users can then reference from the Tor Browser. The system is powered by the Tor network, relies on a distributed database, and provides anonymity to both operators and users. This project aims to address the major usability issue that has been with Tor hidden services since their introduction in 2002.

### Repository Details [![Build Status](https://travis-ci.org/Jesse-V/OnioNS-common.svg?branch=master)](https://travis-ci.org/Jesse-V/OnioNS-common)

This repository provides the common shared library for the other OnioNS packages, -HS, -server, and -client.

### Supported Systems

#### Linux

**Debian 7 and 8, Ubuntu 14.04 - 15.10, Mint 17 - 17.2, Fedora 21 - 23**

i386, amd64, and armhf architectures are supported, so it should run on 32-bit, 64-bit, and ARM machines. I'm also supporting ARM boards such as the Pi, BBB, Odroid, etc.

#### Windows

Not currently supported. I have long-term plans of porting this repository and OnioNS-client to Windows, but no intentions to port the other packages to Windows.

#### OS-X and *BSD

Not currently supported, support planned in the far future. I am willing to provide upstream support to anyone who wishes to port the software over there. I have not attempted to compile this code on any BSD system. My current primary focus is developing the Linux edition.

### Installation

* **Install from PPA**

The tor-onions-common package is a dependency for the other packages, so there is no need to install it manually.

* **Install from .deb file**

I provide builds for Debian Wheezy and Ubuntu in the [Releases section](https://github.com/Jesse-V/OnioNS-common/releases) for amd64, which probably applies to you. For other architectures, you may download from [my PPA](https://launchpad.net/~jvictors/+archive/tor-dev/+packages).

* **Install from source**

> 1. Debian/Ubuntu/Mint: **sudo apt-get install g++ cmake libpopt-dev botan1.10-dev libasio-dev libboost-system-dev**

>> Fedora: **yum install g++ cmake popt-devel botan-devel asio-devel boost-system**

> 2. Download and extract the latest release from the [Releases page](https://github.com/Jesse-V/OnioNS-common/releases).
> 3. **(mkdir build; cd build; cmake ../src; make -j $(grep -c ^processor /proc/cpuinfo); sudo make install)**

If you are actively developing OnioNS, I have actively prepared two scripts, devBuild.sh and checkBuild.sh. Please see them for more information.

You can cleanup your build with **(rm -rf build; cd src/libs/libscrypt; make clean)**
