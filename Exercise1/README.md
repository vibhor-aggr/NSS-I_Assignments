# Exercise 1 - IPTables, NAT, Firewalling, And Linux ACLs

This directory contains:

- `Exercise1.pdf`: original exercise prompt.
- `Exercise1_soln.pdf`: submitted solution/report artifact.

No runnable source code is required for this exercise. The work is a VM-based network and filesystem permissions lab.

## Task 1 Summary

The lab uses three Linux VMs:

- VM1 on subnet 1.
- VM2 as the router/firewall/NAT host with two interfaces.
- VM3 as the web server host.

Required work:

- assign private IP addresses,
- enable IPv4 forwarding on VM2,
- verify routing with ping/traceroute,
- install a web server on VM3,
- configure bidirectional NAT on VM2,
- restrict forwarding to HTTP/HTTPS,
- demonstrate that non-allowed traffic such as SSH is blocked,
- capture NAT/firewall behavior with Wireshark or tcpdump.

## Task 2 Summary

The filesystem portion demonstrates why setting the setuid bit on a web server process is not sufficient to grant arbitrary access to a protected web directory. Linux ACLs are then used to grant explicit read access to the web server process.

## Expected Evidence

The submitted report should contain:

- commands used to configure IP addresses and forwarding,
- routing/traceroute evidence,
- iptables NAT and filter table output,
- tcpdump/Wireshark snippets showing NAT behavior,
- screenshots or logs showing blocked non-HTTP traffic,
- setuid experiment result,
- ACL grant and successful access result.
