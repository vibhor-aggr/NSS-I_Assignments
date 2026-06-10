# Networks and Systems Security Coursework

This repository contains the implementation and lab artifacts for the NSS assignments and exercises.

## Contents

- `Assignment1/`: C implementation of ACL-mediated file and directory commands plus a restricted custom `sudo` wrapper.
- `Assignment2/`: C implementation of secure file copy, KDC-authenticated chat, group messaging, ACL-aware file listing, and TLS file transfer.
- `Exercise1/`: original task PDF and submitted solution PDF for the iptables/NAT/firewall lab.
- `Exercise2/`: original task PDF and submitted solution PDF for eCryptfs, OpenSSL certificate, and TLS tunnel labs.
- `Exercise3/`: LibreSwan IPSec/IKEv2 configuration templates, setup scripts, evidence commands, and report template.

## Build And Test

From this directory:

```sh
make -C Assignment1 clean && make -C Assignment1
make -C Assignment2 clean && make -C Assignment2
Assignment2/tests/secure_copy_test.sh
Assignment2/tests/chat_smoke_test.sh
Assignment2/tests/group_demo.sh
Assignment2/tests/tls_file_test.sh
bash -n Exercise3/scripts/*.sh Assignment2/tests/*.sh
```

Assignment 1 privileged installation is intentionally separate:

```sh
sudo make -C Assignment1 install-privileged
```

Run that only inside the assignment VM where the `fakeroot` user and expected filesystem layout exist.

## OpenSSL Dependency

Assignment 2 builds against `Assignment2/.deps/openssl` when present. `make -C Assignment2 deps` downloads and SHA-verifies OpenSSL 3.5.7 source, then either builds it locally or, when the local Perl install cannot run OpenSSL `Configure`, populates `.deps/openssl` from the existing workspace OpenSSL cache. Details are recorded in `Assignment2/SAFETY.md`.

## Generated Files

Compiled binaries, object files, certificates, packet captures, local OpenSSL dependency trees, and secure-copy demo keys are ignored by `.gitignore`.

## Documentation

Each implemented assignment/exercise directory has its own README. Existing `README.pdf` files in Assignment 1 and Assignment 2 are generated from the corresponding Markdown README so the PDF content matches the current implementation.
