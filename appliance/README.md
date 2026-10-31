# NGCorion virtual appliance

One build produces three images from the same disk:

| File | For |
|---|---|
| `ngcorion-<version>.ova` | VMware vSphere / ESXi 6.5 or later / Workstation 14 or later (hardware version 13: EFI, Secure Boot, pvscsi, vmxnet3) |
| `ngcorion-<version>.vhdx` | Microsoft Hyper-V (Generation 2) |
| `ngcorion-<version>.qcow2` | KVM, Proxmox, OpenStack |

The appliance is Ubuntu 24.04 LTS with Docker and the NGCorion containers
already loaded: it needs no internet access to install or run.

## Building

```bash
appliance/build.sh            # output in appliance/output/<version>/
```

The build host needs Docker, [Packer](https://developer.hashicorp.com/packer)
(the qemu plugin is installed by `packer init`), `qemu-system-x86_64`,
`qemu-img`, `xorriso` and Python 3. With `/dev/kvm` the VM part takes
minutes; on a host without it, `PACKER_ACCELERATOR=tcg` works but is much
slower.

| Variable | Default | Purpose |
|---|---|---|
| `BASE_REGISTRY` | `docker.arvancloud.ir` | Where the base images come from (`docker.io` outside Iran) |
| `PYPI_INDEX`, `NPM_REGISTRY` | Iranian PyPI mirror, npmjs | Package mirrors for the backend image |
| `NGCORION_BACKEND_IMAGE` | (build one) | Package an existing backend image, e.g. the one CI built |
| `PACKER_ACCELERATOR` | `kvm` | `tcg` without hardware virtualisation |
| `BASE_IMAGE_URL`, `BASE_IMAGE_CHECKSUM` | Ubuntu 24.04 cloud image | Another cloud-init image, e.g. Debian 13 `genericcloud` |

What happens:

1. The backend image is built (or `NGCORION_BACKEND_IMAGE` is used); Traefik and
   PostgreSQL are pulled; all three are saved into one archive.
2. Packer boots the Ubuntu cloud image under QEMU. A temporary build account
   (random password per build, set through cloud-init) is the only way in.
3. `provision/10-base.sh` updates the OS, installs Docker and the guest tools
   for VMware, KVM and Hyper-V, and switches networking to systemd-networkd.
4. `provision/20-ngcorion.sh` installs the compose bundle under
   `/opt/ngcorion`, loads the images and the console.
5. `provision/30-harden.sh` locks the machine (below) and installs the
   finalizer, which Packer runs last: it removes the SSH server, cloud-init
   and the build account, clears the machine-id and logs, and powers off.
6. `make-ova.sh` converts the disk into the OVA and the VHDX.

### On GitHub

`.github/workflows/appliance.yml` runs the same `build.sh` on a GitHub runner
(with KVM, `BASE_REGISTRY=docker.io`, PyPI and npmjs instead of the Iranian
mirrors) and attaches the result to a **draft** release:

* push a version tag, e.g. `git tag v2.1.2 && git push origin v2.1.2` (the
  tag must match `VERSION` in `app/core/config.py`), or
* Actions → Appliance → Run workflow (the tag defaults to `v<VERSION>`).
* Actions → Release tag → Run workflow with *build_appliance* (it creates the tag
  and starts this build; a tag pushed by a workflow does not start other
  workflows). The release steps are in `docs/RELEASING.md`.

A draft is visible only to people with write access to the repository; publish
it once the images have been tried. GitHub takes at most 2 GiB per release
file, so larger images are uploaded in parts (`*.part00`, `*.part01`, ...);
the release notes give the command to join them (`cat` on Linux/macOS,
`copy /b` on Windows), and `SHA256SUMS` checks the joined files. Docker Hub
credentials in the repository secrets `DOCKERHUB_USERNAME` /
`DOCKERHUB_TOKEN` are used when present (they avoid Docker Hub's anonymous
pull limit); the build works without them.

## First start

Open the VM's console after the first power-on. The setup asks for:

- host name
- management interface, DHCP or a static address (address/prefix, gateway, DNS)
- NTP servers
- the password of the web administrator `admin` (changed at first login)

The license server is not asked for: it is always `lic.ngcorion.com`, built
into NGCorion. The setup checks that the appliance can reach it (DNS, port
443, a publicly trusted certificate) and says what to fix if not, without
stopping; the menu can check again later.

Nothing changes until the summary is confirmed. Then the appliance writes its
network settings, generates its own secrets (`SECRET_KEY`, the database
password) and a self-signed web certificate, starts NGCorion, creates the
administrator, and shows the web address. The license is activated on the
first page of the web interface.

On vSphere the same values can be given on the "Deploy OVF Template" screen.
When host name and admin password are filled in there, the first start runs
unattended.

## The console

After the first start, the console shows the status (with the disk usage and
SSH) and a menu: network, host name, NTP, a check of the connection to the
license server, using the whole disk, SSH access, restart, the application
log, resetting the web administrator's password, reboot and shut down. There
is no shell and no
login prompt on any terminal; Ctrl-C only returns to the menu.

## Locked down

- SSH is off until turned on from the console ("SSH access"). Then one
  account, `ngcadmin`, gets the console menu and nothing else: sshd's
  ForceCommand runs it through sudo (that one command, no arguments), and
  replaces any command, shell or subsystem (no sftp/scp); no forwarding or
  tunnels; no root login. Password (the admin password rules) and/or public
  keys (ed25519, ECDSA, RSA 3072+), optionally limited to source networks;
  five wrong passwords lock the account for 15 minutes (pam_faillock). Every
  session and every menu action is logged (facility auth). The host keys are
  made when SSH is first turned on, per machine.
- No accounts with a password (but the SSH account's, when one is set), root locked.
- No getty on any virtual terminal or the serial line; Ctrl-Alt-Del disabled.
- GRUB: no menu, no recovery entries, and the entries cannot be edited (the
  GRUB password is random per build and discarded), which closes the
  `init=/bin/sh` route to a root shell.
- Every deployed appliance creates its own machine-id, SSH-free identity,
  secrets and certificate on first boot; nothing secret is in the image.
- The OVA enables EFI with Secure Boot (Ubuntu's signed boot chain).

## The disk

The image's disk is 60 GB. Enlarge the virtual disk in the hypervisor (remove
snapshots first on ESXi): at the next start ngcorion-growdisk.service grows
the system partition and its filesystem online (growpart, resize2fs), or at
once with the console's "Use the whole disk (after enlarging it)". A second
disk is not used.

Not done yet: an encrypted disk tied to the license, a read-only root
filesystem and signed appliance updates.

## Code

`ngcorion_appliance/` (Python standard library only, runs on the appliance):

| Module | |
|---|---|
| `settings.py` | what can be configured, and its validation |
| `render.py` | the files those settings become (networkd, hosts, timesyncd, `.env`) |
| `ovf.py` | reading vCenter's OVF properties |
| `system.py` | applying settings to the machine; the license server connection check |
| `wizard.py` | the first-start questions and the setup sequence |
| `console.py` | the menu |

Tests: `tests/test_appliance.py` (part of the normal pytest run).
