# Project Goals

Our goal is creating a **hardened Kali Linux press containing a self-learning IDS**. All development efforts should align with this objective.

- Automate the installation and configuration of Kali Linux with strong security defaults.
- Train and run a neural network-based IDS leveraging legal datasets.
- Provide optional host-hardening tools for Windows environments.
- Keep documentation and scripts modular for easy customization.
- Include a secure development environment with git best practices.
- Extend the secure coding environment with static analysis tools, secret scanning, and mandatory commit signing. A GPG key should be generated automatically so all commits are verifiable.
- Implement self-healing capabilities that snapshot and restore IDS data to recover from wipe attempts.
- Run an initial network discovery after setup to capture a baseline of hosts and services.
