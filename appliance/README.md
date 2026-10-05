# NGCorion virtual appliance

One build produces three images from the same disk:

| File | For |
|---|---|
| `ngcorion-<version>.ova` | VMware vSphere / ESXi / Workstation (EFI, Secure Boot, pvscsi, vmxnet3) |
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

1. The backend image is built (or `NGCORION_BACKEND_IMAGE` is used); Traefik,
   PostgreSQL and Redis are pulled; all four are saved into one archive.
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

## First start

Open the VM's console after the first power-on. The setup asks for:

- host name
- management interface, DHCP or a static address (address/prefix, gateway, DNS)
- NTP servers
- the license server's address (`https://...`). A self-signed license server
  certificate is shown with its SHA-256 fingerprint; compare it with the one
  the license server shows (`openssl x509 -in <cert> -noout -fingerprint -sha256`)
  before accepting it.
- the password of the web administrator `admin` (changed at first login)

Nothing changes until the summary is confirmed. Then the appliance writes its
network settings, generates its own secrets (`SECRET_KEY`, the database
password) and a self-signed web certificate, starts NGCorion, creates the
administrator, and shows the web address. The license is activated on the
first page of the web interface.

On vSphere the same values can be given on the "Deploy OVF Template" screen
(including the license server fingerprint). When host name, license server
and admin password are filled in there, the first start runs unattended.

## The console

After the first start, the console shows the status and a menu: network,
host name, NTP, license server, restart, the application log, resetting the
web administrator's password, reboot and shut down. There is no shell and no
login prompt on any terminal; Ctrl-C only returns to the menu.

## Locked down

- No SSH server, no accounts with a password, root locked.
- No getty on any virtual terminal or the serial line; Ctrl-Alt-Del disabled.
- GRUB: no menu, no recovery entries, and the entries cannot be edited (the
  GRUB password is random per build and discarded), which closes the
  `init=/bin/sh` route to a root shell.
- Every deployed appliance creates its own machine-id, SSH-free identity,
  secrets and certificate on first boot; nothing secret is in the image.
- The OVA enables EFI with Secure Boot (Ubuntu's signed boot chain).

Not done yet: an encrypted disk tied to the license, a read-only root
filesystem and signed appliance updates.

## Code

`ngcorion_appliance/` (Python standard library only, runs on the appliance):

| Module | |
|---|---|
| `settings.py` | what can be configured, and its validation |
| `render.py` | the files those settings become (networkd, hosts, timesyncd, `.env`) |
| `ovf.py` | reading vCenter's OVF properties |
| `system.py` | applying settings to the machine; the license server certificate |
| `wizard.py` | the first-start questions and the setup sequence |
| `console.py` | the menu |

Tests: `tests/test_appliance.py` (part of the normal pytest run).
