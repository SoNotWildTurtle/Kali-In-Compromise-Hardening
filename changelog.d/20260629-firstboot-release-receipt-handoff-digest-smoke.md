# Firstboot release receipt handoff digest smoke

- Added passive release receipt handoff digest smoke evidence for firstboot final-readiness handoff.
- Packaged `firstboot_final_readiness_release_receipt_handoff_digest_smoke.py` in the custom ISO build helper.
- Wired JSON, Markdown, and `.summary.env` handoff digest smoke artifacts into `firstboot_release_gate.service`.
- Documented threat-model rationale, rollback notes, safe automation boundaries, release-gate behavior, and follow-up work.
