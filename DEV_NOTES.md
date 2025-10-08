# Developer Notes

This project automates the creation of a secure Kali Linux ISO and the hardening of both the VM and a Windows host. Modules referenced in `README.md` should remain self-contained so they can be included in the ISO build.

## Contributing

- Follow POSIX shell best practices; run `bash -n <script>` before committing.
- Validate Python modules with `python3 -m py_compile`.
- Document new routes or scripts in the README under *Project Structure*.
- Keep goals in `GOALS.md` aligned with ongoing development.
- Ensure `secure_dev_env.sh` configures secure git defaults, pre-commit tooling, and is triggered during first boot.
- The script now auto-generates a GPG key for commit signing; use `git config --global user.name` and `user.email` to personalize the key.
- Run `pre-commit run --all-files` to execute static analysis and secret scanning (Black, Flake8, Bandit, ShellCheck, isort, Codespell, Gitleaks) before committing changes.
- When modifying IDS components, ensure `nn_ids_snapshot.py` and `nn_ids_restore.py` continue to function for self-healing.
- `network_discovery.sh` logs its output to `/home/kali/Desktop/initial network discovery`; adjust paths if user accounts change.
