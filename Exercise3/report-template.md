# Exercise 3 Report Template

## Environment

- Virtualization platform:
- VM operating system:
- VM1 IP/interface:
- VM2 IPs/interfaces:
- VM3 IPs/interfaces:
- VM4 IP/interface:

## Certificate Setup

Commands run:

```sh
./scripts/generate-certs.sh certs
```

Evidence to paste:

- CA certificate creation output.
- VM2/VM3 certificate import output.

## Tunnel Mode IPSec/IKEv2

Commands run on VM2:

```sh
sudo ./scripts/setup-vm2-gateway.sh
```

Commands run on VM3:

```sh
sudo ./scripts/setup-vm3-gateway.sh
```

Validation:

```sh
sudo ipsec status
sudo ip xfrm state
sudo ip xfrm policy
```

Evidence to paste:

- `ipsec status` from both gateways.
- Wireshark/tcpdump capture showing IKE and ESP between `20.0.0.2` and `20.0.0.3`.
- VM1 `ping -c 4 30.0.0.10`.

## Traffic Selector

Commands run on VM4:

```sh
sudo ./scripts/setup-vm4-webserver.sh
```

Commands run on VM1:

```sh
wget -O - http://30.0.0.10/nss-ex3/index.txt
nc -vz 30.0.0.10 22 || true
```

Evidence to paste:

- Successful `wget` to VM4 port 80.
- Failed non-web connection after web-only selector is active.
- ESP packets in gateway capture during web request.

## Transport Mode

Commands:

```sh
sudo ipsec auto --down nss-tunnel || true
sudo ipsec auto --add nss-transport
sudo ipsec auto --up nss-transport
```

Evidence to paste:

- Transport-mode `ipsec status`.
- Packet capture showing protected traffic between VM2 and VM3.

## Assumptions

- VM2 and VM3 have LibreSwan installed.
- VM2 and VM3 can reach each other on `20.0.0.0/24`.
- VM1 routes traffic for `30.0.0.0/24` via VM2, and VM4 routes traffic for `10.0.0.0/24` via VM3.
