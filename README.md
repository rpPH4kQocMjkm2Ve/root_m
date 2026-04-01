# root-chezmoi — Arch Linux system configuration

[![CI](https://github.com/rpPH4kQocMjkm2Ve/root-chezmoi/actions/workflows/ci.yml/badge.svg)](https://github.com/rpPH4kQocMjkm2Ve/root-chezmoi/actions/workflows/ci.yml)
![License](https://img.shields.io/github/license/rpPH4kQocMjkm2Ve/root-chezmoi)

System-level configuration files (`/etc`, `/efi`) managed with
[chezmoi](https://www.chezmoi.io/) using `destDir = "/"`.

## What's included

- **Atomic upgrades**: via [atomic-upgrade](https://gitlab.com/fkzys/atomic-upgrade) (per-host config override)
- **Boot**: systemd-boot with signed UKI (Secure Boot via sbctl)
- **Filesystem**: Btrfs on LUKS, automated snapshots via btrbk
- **Network**: systemd-networkd (wired + wifi)
- **Firewall**: firewalld with per-user network blocking and trusted zone templating
- **Containers**: Podman with btrfs storage driver
- **Hardening**: kernel sysctl, faillock, coredump off, USB lock, pam, [hardened\_malloc](https://gitlab.com/fkzys/hardened-malloc)
- **Nextcloud blocking**: pacman hook prevents Nextcloud installation
  for user\_c (controlled by `block_nextcloud_user_c` flag)
- **Declarative permissions**: custom permission system replacing `.chezmoiattributes` — glob-based rules for mode/owner/group with full test coverage

## Permissions

chezmoi's built-in `.chezmoiattributes` is replaced by a custom system:

- **`chezmoiperms`** — declarative rules file (glob pattern + mode + owner + group per line)
- **`scripts/apply_perms.py`** — parser and applicator (pure-function pipeline, no chezmoi subprocess dependency)
- **`Makefile`** — `make perms` target that pipes `chezmoi managed` into `apply_perms.py`

### Rule format

```
<glob-pattern>   <mode|->  <owner|->  <group|->
```

- Pattern ending with `/` matches directories only; without — files only
- `**` matches zero or more path segments, `*` matches within a single segment
- `-` means "don't change this attribute"
- Last matching rule wins

### Current rules

```
etc/**                   0644  root  root
etc/**/                  0755  root  root
etc/security/**          0600  root  root
etc/pacman.conf          0644  root  root
etc/polkit-1/rules.d/**  0750  root  polkitd
efi/**                   0755  root  root
root/**                  0600  root  root
root/**/                 0700  root  root
```

### Usage

```bash
# Apply permissions to all chezmoi-managed paths
sudo make perms

# Dry run (print what would change)
make dry-run
```

### Tests

See [tests/README.md](tests/README.md) for test documentation. Tests cover parsing, glob matching, action computation, and filesystem integration (chmod/chown). CI runs lint (`ruff`, `mypy --strict`) and tests as root on every push/PR.

## hardened\_malloc

Installed as a separate package via [gitpkg](https://gitlab.com/fkzys/gitpkg):

```bash
gitpkg install hardened_malloc
```

See [hardened\_malloc](https://gitlab.com/fkzys/hardened_malloc) for details on variants, fake\_rlimit shim, and compatibility notes.

## Atomic upgrade overrides

The [atomic-upgrade](https://gitlab.com/fkzys/atomic-upgrade) package is installed separately. This repo provides:

- **`/etc/atomic.conf`** — per-host kernel parameters (TPM2 auto-unlock, etc.) via chezmoi template

## Firewall

[firewalld](https://firewalld.org/) configuration is templated with secrets from SOPS.

### Per-user network blocking

When `block_network_user_c` is enabled, firewalld direct rules drop all outbound IPv4/IPv6 traffic for the specified UID via iptables `owner` match:

```xml
<rule ipv="ipv4" table="filter" chain="OUTPUT" priority="0">-m owner --uid-owner <UID> -j DROP</rule>
<rule ipv="ipv6" table="filter" chain="OUTPUT" priority="0">-m owner --uid-owner <UID> -j DROP</rule>
```

The UID is read from `secrets.enc.yaml` (`users.user_c.uid`).

### Trusted zone

The trusted zone template adds:
- `tun0` interface (VPN)
- Local subnet and Podman subnet as trusted sources

Subnet values are stored encrypted in `secrets.enc.yaml` (`firewall.subnet1`, `firewall.podman_subnet`).

## Structure

```
.
├── Makefile                          # make perms — apply permissions
├── chezmoiperms                      # Declarative permission rules
├── secrets.enc.yaml                  # SOPS-encrypted secrets (age)
├── scripts/
│   └── apply_perms.py                # Permission parser and applicator
├── tests/
│   ├── README.md                     # Test documentation
│   └── test_apply_perms.py           # pytest suite (unit + integration)
├── efi/
│   └── loader/
│       └── executable_loader.conf    # systemd-boot config
├── etc/
│   ├── atomic.conf.tmpl              # atomic-upgrade config override
│   ├── btrbk/
│   │   ├── btrbk.conf.example        # Snapshot policy example
│   │   └── btrbk.conf.tmpl           # Snapshot policy (per-host)
│   ├── containers/
│   │   └── storage.conf.tmpl         # Podman (btrfs driver, per-host graphroot)
│   ├── firewalld/
│   │   ├── direct.xml.tmpl           # Per-user outbound block (iptables owner match)
│   │   └── zones/
│   │       └── trusted.xml.tmpl      # Trusted zone (VPN, subnets)
│   ├── mkinitcpio.conf               # Initramfs base config
│   ├── mkinitcpio.conf.d/
│   │   └── 10-default.conf.tmpl      # Drop-in (per-host nvidia modules)
│   ├── mkinitcpio.d/
│   │   └── linux.preset              # Preset
│   ├── modprobe.d/
│   │   └── 10-nvidia.conf            # NVIDIA kernel module options
│   ├── modules-load.d/
│   │   └── modules.conf              # Kernel modules to load at boot
│   ├── pacman.conf                   # Pacman configuration
│   ├── pacman.d/
│   │   └── hooks/
│   │       └── block-nextcloud-user_c.hook  # Nextcloud blocking hook
│   ├── pam.d/
│   │   └── login                     # PAM (gnome-keyring auto-unlock)
│   ├── polkit-1/
│   │   └── rules.d/
│   │       └── 99-sing-box.rules.tmpl  # Polkit rules (sing-box DNS)
│   ├── security/
│   │   └── faillock.conf             # Account lockout policy
│   ├── sysctl.d/
│   │   └── 10-default.conf           # Kernel parameters
│   ├── systemd/
│   │   ├── coredump.conf             # Coredump disabled
│   │   ├── journald.conf             # Journal settings
│   │   ├── network/
│   │   │   ├── 10-wire.network       # Wired network
│   │   │   └── 11-wifi.network       # WiFi network
│   │   └── zram-generator.conf       # Zram swap
│   └── tmpfiles.d/
│       ├── battery.conf              # Battery charge thresholds
│       └── usb-lock.conf             # USB authorization lock
├── root/
│   └── dot_zshrc                     # Root shell config
├── usr/
│   └── local/
│       └── bin/                      # Custom scripts
└── .github/
    └── workflows/
        └── ci.yml                    # Lint + test pipeline
```

## Per-host configuration

Feature flags are set via `chezmoi init` prompts and stored in `/root/.config/chezmoi/chezmoi.toml`:

| Variable | Description |
|---|---|
| `nvidia` | NVIDIA GPU (mkinitcpio modules, modprobe config) |
| `tpm2_unlock` | TPM2 LUKS auto-unlock (`rd.luks.options=tpm2-device=auto`) |
| `laptop` | Battery charge thresholds (tmpfiles) |
| `block_nextcloud_user_c` | Block Nextcloud access for user\_c |
| `block_network_user_c` | Block all network access for user\_c (firewalld direct rules) |

Per-host data (btrbk targets, podman graphroot, firewall subnets, user UIDs) is stored in `secrets.enc.yaml`, keyed by hostname or category.

## Secrets

Encrypted with [SOPS](https://github.com/getsops/sops) + [age](https://github.com/FiloSottile/age).

Each machine has its own age key, stored separately from this repo.

### Structure

```yaml
# secrets.enc.yaml (decrypted view)
polkit:
    username: "actual_username"
firewall:
    subnet1: "192.168.x.x/24"
    podman_subnet: "10.x.x.x/16"
users:
    user_c:
        uid: 1001
```

Templates access secrets via:

```
{{ $s := output "sops" "-d" (joinPath .chezmoi.sourceDir "secrets.enc.yaml") | fromYaml -}}
{{ index $s "polkit" "username" }}
```

### Setup on a new machine

1. Create age key:
```bash
sudo mkdir -p /root/.config/chezmoi
sudo age-keygen -o /root/.config/chezmoi/key.txt
```

2. Add public key to `.sops.yaml` and re-encrypt:
```bash
# Edit .sops.yaml, add new recipient
sops updatekeys secrets.enc.yaml
```

3. Apply:
```bash
sudo chezmoi init --apply <GIT_URL>
```

## Post-install

```bash
# Install hardened_malloc
gitpkg install hardened_malloc

# Install atomic-upgrade
gitpkg install atomic-upgrade

# Enable zram
sudo systemctl start systemd-zram-setup@zram0.service

# Create snapshot directories for btrbk
sudo mkdir -p /snapshots/{root,home}
sudo systemctl enable --now btrbk.timer
```

## Dependencies

### Required

- `chezmoi` — configuration management
- `sops` + `age` — secret encryption

### Optional

- [hardened\_malloc](https://gitlab.com/fkzys/hardened_malloc) — hardened memory allocator (via [gitpkg](https://gitlab.com/fkzys/gitpkg))
- [atomic-upgrade](https://gitlab.com/fkzys/atomic-upgrade) — atomic system upgrades (via [gitpkg](https://gitlab.com/fkzys/gitpkg) or [AUR](https://aur.archlinux.org/packages/atomic-upgrade))
- `btrbk` — automated Btrfs snapshots
- `podman` — containers (btrfs storage driver)
- `firewalld` — firewall with per-user blocking and trusted zones

## License

AGPL-3.0-or-later
