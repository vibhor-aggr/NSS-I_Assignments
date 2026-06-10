# Exercise 3 - LibreSwan IPSec/IKEv2 Lab

This directory contains reproducible artifacts for the four-VM LibreSwan IPSec/IKEv2 topology in `Exercise3.pdf`.

The scripts are not meant to run on this development host. They must be copied to the relevant VMs and run as root because they modify network interfaces, firewall rules, LibreSwan state, and system services.

## Files

- `topology.env`: default IP/interface variables from the PDF topology.
- `configs/vm2-ipsec.conf`: LibreSwan config for VM2.
- `configs/vm3-ipsec.conf`: LibreSwan config for VM3.
- `scripts/generate-certs.sh`: creates a CA and VM2/VM3 certificates.
- `scripts/setup-vm2-gateway.sh`: enables forwarding and installs VM2 config.
- `scripts/setup-vm3-gateway.sh`: enables forwarding and installs VM3 config.
- `scripts/setup-vm4-webserver.sh`: creates test web content and starts a web server.
- `scripts/capture-evidence.sh`: prints tcpdump, ping, wget, and state-inspection commands.
- `report-template.md`: fill-in report outline matching the exercise rubric.

## Default Topology

- VM1: client on `10.0.0.0/24`, expected IP `10.0.0.10`.
- VM2: IPSec gateway, `10.0.0.1/24` and `20.0.0.2/24`.
- VM3: IPSec gateway, `20.0.0.3/24` and `30.0.0.1/24`.
- VM4: web server on `30.0.0.10/24`.

Edit `topology.env` before use if interface names or IP addresses differ.

## Required Packages On VMs

VM2 and VM3:

```sh
sudo apt-get install libreswan tcpdump iproute2 iptables
```

VM4:

```sh
sudo apt-get install apache2
```

Use the equivalent package manager commands on non-Debian systems.

## Run Order

1. Generate certificates from a trusted workstation or one of the VMs:

   ```sh
   ./scripts/generate-certs.sh certs
   ```

2. Copy the CA and VM-specific cert/key material to the gateways.

3. Import certificates into LibreSwan NSS databases on VM2 and VM3. The certificate script prints the exact `certutil`, `pk12util`, and `openssl pkcs12` commands.

4. Configure VM2:

   ```sh
   sudo ./scripts/setup-vm2-gateway.sh
   ```

5. Configure VM3:

   ```sh
   sudo ./scripts/setup-vm3-gateway.sh
   ```

6. Configure VM4 web content:

   ```sh
   sudo ./scripts/setup-vm4-webserver.sh
   ```

7. Use `scripts/capture-evidence.sh` to print the validation and capture commands.

## Validation Commands

On VM2 and VM3:

```sh
sudo ipsec status
sudo ip xfrm state
sudo ip xfrm policy
```

On VM1:

```sh
ping -c 4 30.0.0.10
wget -O - http://30.0.0.10/nss-ex3/index.txt
nc -vz 30.0.0.10 22 || true
```

On either gateway, capture IKE and ESP:

```sh
sudo tcpdump -i <gateway-interface> -w gateway-ike-esp.pcap 'udp port 500 or udp port 4500 or esp'
```

## Expected Evidence

Capture screenshots or terminal logs showing:

- `ipsec status` on VM2 and VM3 after tunnel establishment,
- Wireshark/tcpdump traffic showing IKE setup and ESP packets between VM2 and VM3,
- VM1 successfully pinging VM4 through the tunnel,
- VM1 successfully using `wget` against VM4 port 80,
- non-web traffic blocked when the web-only traffic selector is active,
- transport-mode status and packet capture if the optional transport-mode validation is performed.

## Assumptions

- VM2 and VM3 can reach each other on `20.0.0.0/24`.
- VM1 routes `30.0.0.0/24` traffic through VM2.
- VM4 routes `10.0.0.0/24` traffic through VM3.
- LibreSwan is installed and can manage `/etc/ipsec.conf`.
