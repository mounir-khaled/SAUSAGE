# SAUSAGE

SAUSAGE is a static analysis tool that identifies accessible Unix domain sockets given an Android firmware image. SAUSAGE relies on [BigMAC](https://github.com/FICS/BigMAC) to process Android security policies from Android firmware. It queries BigMAC for the system services that an untrusted app can communicate with using Unix domain sockets according to the firmware's SELinux policy. For each of these service binaries, SAUSAGE performs dataflow analysis in order to recover the types, addresses, and permissions of these sockets. This repository contains the binary analysis component of SAUSAGE. Given an Android system service binary, this component extracts the addresses and types of the sockets that the service creates, as well as any security checks based on the connecting client's credentials. For details about the design and implementation of SAUSAGE, please refer to the publication.

## Installation

SAUSAGE depends on a slightly modified version of angr forked from v9.0.4940. To install it, clone the forked repo:

```
$ git clone https://github.com/mounir-khaled/angr && cd angr
```

Checkout the `SAUSAGE` branch
```
$ git checkout SAUSAGE
```

Install angr
```
$ pip install .
```

## Usage

To extract socket addresses from a binary:

```
$ python3 run.py <path to binary> <ld_path(s)>
```

The first argument is the binary to analyze. The remaining arguments (ld_path) are paths to directories in which to search for dynamically linkable libraries that the binary uses. 
The output of this tool is a JSON-formatted report of all of the extracted sockets, as well as any access control checks that the service binary performs depending on the client's credentials.

## PoCs of discovered vulnerabilities

- CVE-2021-25461 | PoC: https://github.com/mounir-khaled/CVE-2021-25461

## Publication

M. Elgharabawy, B. Kojusner, M. Mannan, K. R. B. Butler, B. Williams and A. Youssef, "SAUSAGE: Security Analysis of Unix domain Socket usAGE in Android," 2022 IEEE 7th European Symposium on Security and Privacy (EuroS&P), 2022, pp. 572-586, doi: 10.1109/EuroSP53844.2022.00042.

Full-text: https://users.encs.concordia.ca/~mmannan/publications/Android-Sockets-EuroSP-2022.pdf

