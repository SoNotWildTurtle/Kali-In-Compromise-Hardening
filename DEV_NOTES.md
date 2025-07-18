# Developer Notes

This project automates the creation of a secure Kali Linux ISO and the hardening of both the VM and a Windows host. Modules referenced in `README.md` should remain self-contained so they can be included in the ISO build.

## Contributing

- Follow POSIX shell best practices; run `bash -n <script>` before committing.
- Validate Python modules with `python3 -m py_compile`.
- Document new routes or scripts in the README under *Project Structure*.
- Keep goals in `GOALS.md` aligned with ongoing development.
