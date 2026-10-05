# NGCorion virtual appliance: one qcow2 disk image, from which build.sh makes
# the OVA (VMware), the VHDX (Hyper-V) and keeps the qcow2 (KVM/Proxmox).
#
# Base: the Ubuntu 24.04 LTS cloud image. Any cloud image with cloud-init
# works the same way (e.g. Debian 13 genericcloud): set base_image_url and
# base_image_checksum.
#
# Run through appliance/build.sh, which prepares the stage directory and the
# per-build password.

packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = ">= 1.1.0"
    }
  }
}

variable "version" {
  type = string
}

variable "build_password" {
  type      = string
  sensitive = true
}

variable "stage_dir" {
  type = string
}

variable "output_dir" {
  type = string
}

variable "base_image_url" {
  type    = string
  default = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
}

variable "base_image_checksum" {
  type    = string
  default = "file:https://cloud-images.ubuntu.com/noble/current/SHA256SUMS"
}

variable "disk_size" {
  type    = string
  default = "60G"
}

# "kvm" on a build host with /dev/kvm; "tcg" (software emulation, much slower) without.
variable "accelerator" {
  type    = string
  default = "kvm"
}

source "qemu" "ngcorion" {
  iso_url          = var.base_image_url
  iso_checksum     = var.base_image_checksum
  disk_image       = true
  disk_size        = var.disk_size
  disk_compression = true
  format           = "qcow2"
  accelerator      = var.accelerator
  cpus             = 2
  memory           = 4096
  headless         = true
  net_device       = "virtio-net"
  disk_interface   = "virtio"

  cd_label = "cidata"
  cd_content = {
    "meta-data" = file("${path.root}/cloud-init/meta-data")
    "user-data" = templatefile("${path.root}/cloud-init/user-data.pkrtpl", { password = var.build_password })
  }

  communicator     = "ssh"
  ssh_username     = "packer"
  ssh_password     = var.build_password
  ssh_timeout      = "90m"
  shutdown_command = "sudo /usr/local/sbin/ngcorion-finalize"
  shutdown_timeout = "30m"

  output_directory = var.output_dir
  vm_name          = "ngcorion-${var.version}.qcow2"
}

build {
  sources = ["source.qemu.ngcorion"]

  provisioner "shell" {
    # A file provisioner whose source ends in "/" copies into an existing directory.
    inline = ["cloud-init status --wait || true", "mkdir -p /tmp/stage /tmp/rootfs"]
  }

  provisioner "file" {
    source      = "${var.stage_dir}/"
    destination = "/tmp/stage"
  }

  provisioner "file" {
    source      = "${path.root}/../rootfs/"
    destination = "/tmp/rootfs"
  }

  provisioner "shell" {
    execute_command  = "sudo -E sh -eux '{{ .Path }}'"
    environment_vars = ["NGCORION_VERSION=${var.version}"]
    scripts = [
      "${path.root}/../provision/10-base.sh",
      "${path.root}/../provision/20-ngcorion.sh",
      "${path.root}/../provision/30-harden.sh",
    ]
  }
}
