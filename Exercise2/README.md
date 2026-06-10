# Exercise 2 - eCryptfs, OpenSSL Certificates, And TLS Tunneling

This directory contains:

- `Exercise2.pdf`: original exercise prompt.
- `Exercise2_soln.pdf`: submitted solution/report artifact.

No runnable source code is required for this exercise. The work is a VM-based system security lab.

## Part 1 - Directory Encryption With eCryptfs

Required work:

- install `ecryptfs-utils`,
- create an encrypted directory,
- mount it with eCryptfs,
- write a plaintext file while mounted,
- unmount and show encrypted on-disk contents,
- remount and show decrypted contents.

## Part 2 - OpenSSL Certificates

Required work:

- create a CA key and root certificate,
- create server and client private keys,
- generate CSRs,
- sign client and server certificates with the CA,
- run `openssl s_server`,
- connect with `openssl s_client`,
- demonstrate server certificate validation,
- demonstrate mutual TLS by requiring and presenting the client certificate,
- run `s_server -www` and verify certificate information from a browser.

## Part 3 - NFSv4 Over TLS

Required work:

- configure NFS server/client access,
- capture unencrypted NFS traffic,
- configure `stunnel4` with a self-signed certificate,
- route NFS traffic through the TLS tunnel,
- capture encrypted traffic after tunneling.

## Expected Evidence

The submitted report should contain command logs and screenshots for:

- encrypted and decrypted eCryptfs file views,
- CA/client/server certificate generation,
- OpenSSL client/server verification output,
- mutual authentication output,
- NFS read/write before tunneling,
- NFS read/write after TLS tunneling,
- tcpdump/Wireshark evidence for plaintext versus encrypted transport.
