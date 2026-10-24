# Versions and releases

How NGCorion is versioned, tagged and delivered (configuration management and
delivery; the AFTA / Common Criteria classes ALC_CMC, ALC_CMS and ALC_DEL in
`docs/SECURITY_TARGET.md`).

## Version numbers

[Semantic Versioning](https://semver.org): `MAJOR.MINOR.PATCH`, with
`-rc.N` for a release candidate.

* PATCH — fixes only; MINOR — new features, compatible upgrades (database
  migrations run by themselves); MAJOR — an upgrade that needs a manual step.
* The version lives in one place, `VERSION` in `app/core/config.py`; the web
  UI's `front/package.json` carries the same number. `/health` reports it,
  and backups record it.

## Tags

Every release is an annotated git tag `vX.Y.Z` (or `vX.Y.Z-rc.N`) on `main`,
and it must equal `VERSION` (the appliance workflow refuses a mismatch).
Tags are never moved or deleted once pushed; a fix gets a new number.

| Tag | Commit | |
|---|---|---|
| `v2.0.0` | `7f5be33` | 2026-10-04; not on GitHub as a tag yet. The draft release "NGCorion 2.0.0 appliance" was built from `11f65b0` (20 commits later, before VERSION moved on), so it is not this commit |
| `v2.1.0` | the "Version 2.1.0" commit | 2026-10-17; first release with the license server key built in (`02f8c805e424e285`). The release candidate `2.1.0-rc.1` was never tagged |
| `v2.1.1` | `5e1ae2c` | 2026-10-24; tagged by the Release tag workflow, without an appliance build |
| `v2.1.2` | the "Version 2.1.2" commit | 2026-10-24; security review (OWASP WSTG) fixes, documents up to date; tagged with the appliance build |

## Making a release

1. `main` is green in CI (tests, lint, build, dependency audit).
   `TRUSTED_LICENSE_KEYS` in `app/core/license_keys.py` holds the license
   server's public key; the Release tag and appliance workflows refuse to tag or
   build without it, since such a build refuses every license.
2. Set `VERSION` and `front/package.json` (`npm version X.Y.Z --no-git-tag-version`
   in `front/`), and give the `CHANGELOG.md` section its number and date.
3. Commit and push, then tag: GitHub → Actions → **Release tag** → Run workflow
   with the version (it refuses a version that differs from the code, and never
   moves an existing tag). Or by hand:

   ```sh
   git tag -a vX.Y.Z -m "NGCorion X.Y.Z"
   git push origin vX.Y.Z
   ```
4. The tag starts `.github/workflows/appliance.yml` (the Release tag workflow
   starts it itself): it builds the OVA, VHDX and
   qcow2 from that commit, the software bill of materials (CycloneDX, Python and
   web UI), the Persian documents as PDF (user and admin guides, security
   architecture, Security Target, product overview, training course;
   `scripts/docs_pdf.py`) and `SHA256SUMS`, and
   attaches them to a **draft** GitHub release. CI prints the same PDFs on
   every push (artifact `ngcorion-docs-fa-pdf`).
5. Try the images (at least VMware ESXi), then publish the draft.

## Delivery and its verification

The customer receives the files of the release and checks them against
`SHA256SUMS` before importing (`sha256sum -c SHA256SUMS`); files over 2 GiB come
in parts, joined as the release notes describe. Everything in an image is
built from the tagged commit by the workflow, on GitHub's runners, with pinned
base images and locked dependencies (`uv.lock`, `front/package-lock.json`).
