---
description: Reset this DFIR workspace for a new case (cleans evidence and case references)
---
Reset this workspace for a new case. This is a deliberate, destructive maintenance
operation -- the workspace's "do not delete evidence" rule does not apply to it,
but it must NEVER be used on a live case mid-investigation.

Work through this carefully:

1. Run the dry-run and show me exactly what would be removed:

   !`./reset_case.sh`

2. Explain what survives: `docker/` (image + helpers), `skills/`, `.opencode/`,
   `opencode.jsonc`, `AGENTS.md`, `CLAUDE.md`, `README.md`, `reset_case.sh`,
   `.gitignore`, and every `.gitkeep`.

3. Report the detected case name and confirm I have archived any evidence I still
   need. Then **ask me to confirm** before deleting anything. Do not proceed
   without an explicit yes.

4. Only after I confirm, run the real reset. Pass through any flags I gave in
   `$ARGUMENTS` (e.g. `--keep-evidence`, `--scrub-refs`, `--reset-git`):

   ```sh
   ./reset_case.sh --yes $ARGUMENTS
   ```

5. Re-verify the reusable tree is intact, report any residual case references
   from the post-run scan, and summarise what was removed.

If I pass `--keep-evidence`, keep `evidences/` intact and reset only
`analysis/`, `reports/` and `notes/`.
