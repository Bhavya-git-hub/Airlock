#!/usr/bin/env bash
# Airlock — one-time WSL setup for the parts that need root.
#
# Go and Rust are already installed under $HOME and needed no sudo. This script
# handles the three things that do:
#
#   1. Docker Engine (NOT Docker Desktop — saves ~1 GB resident on an 8 GB box)
#   2. gVisor (runsc)      — the default sandbox backend
#   3. Firecracker + KVM   — the showcase backend; needs you in the kvm group
#
# Run it once:
#   bash scripts/setup-wsl.sh
#
# It is idempotent: safe to re-run if a step fails partway.

set -euo pipefail

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*"; }

[[ $EUID -eq 0 ]] && { echo "Run as your normal user, not root — the script calls sudo itself."; exit 1; }
grep -qi microsoft /proc/version || warn "This does not look like WSL. Continuing anyway."

ARCH="$(dpkg --print-architecture)"
CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"

# ---------------------------------------------------------------- 0. prereqs
log "Installing prerequisites"
sudo apt-get update -qq
sudo apt-get install -y -qq ca-certificates curl gnupg lsb-release jq bc >/dev/null
ok "ca-certificates, curl, gnupg, jq, bc"

# ---------------------------------------------------------------- 1. docker
if command -v docker >/dev/null 2>&1; then
  ok "Docker already installed: $(docker --version)"
else
  log "Installing Docker Engine"
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${CODENAME} stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update -qq
  sudo apt-get install -y -qq \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
  ok "Docker Engine + compose plugin installed"
fi

sudo systemctl enable --now docker >/dev/null 2>&1 || sudo service docker start || true
ok "Docker daemon started"

# ---------------------------------------------------------------- 2. gvisor
if command -v runsc >/dev/null 2>&1; then
  ok "gVisor already installed: $(runsc --version | head -1)"
else
  log "Installing gVisor (runsc)"
  curl -fsSL https://gvisor.dev/archive.key \
    | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [arch=${ARCH} signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
    | sudo tee /etc/apt/sources.list.d/gvisor.list >/dev/null
  sudo apt-get update -qq
  sudo apt-get install -y -qq runsc >/dev/null
  ok "gVisor installed: $(runsc --version | head -1)"
fi

log "Registering runsc as a Docker runtime"
# systrap is the default platform and needs no KVM — important, because CI
# runners will not have nested virtualization.
sudo runsc install >/dev/null 2>&1 || warn "runsc install reported an issue; check /etc/docker/daemon.json"
sudo systemctl restart docker >/dev/null 2>&1 || sudo service docker restart || true
ok "runsc registered (verify with: docker info | grep -i runtime)"

# ---------------------------------------------------------------- 3. firecracker
if command -v firecracker >/dev/null 2>&1; then
  ok "Firecracker already installed: $(firecracker --version | head -1)"
else
  log "Installing Firecracker"
  FC_ARCH="$(uname -m)"
  FC_TAG="$(curl -fsSL https://api.github.com/repos/firecracker-microvm/firecracker/releases/latest | jq -r .tag_name)"
  [[ -z "$FC_TAG" || "$FC_TAG" == "null" ]] && { warn "Could not resolve latest Firecracker release; skipping"; FC_TAG=""; }
  if [[ -n "$FC_TAG" ]]; then
    TMP="$(mktemp -d)"
    curl -fsSL -o "$TMP/fc.tgz" \
      "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_TAG}/firecracker-${FC_TAG}-${FC_ARCH}.tgz"
    tar -xzf "$TMP/fc.tgz" -C "$TMP"
    sudo install -m 0755 "$TMP/release-${FC_TAG}-${FC_ARCH}/firecracker-${FC_TAG}-${FC_ARCH}" /usr/local/bin/firecracker
    sudo install -m 0755 "$TMP/release-${FC_TAG}-${FC_ARCH}/jailer-${FC_TAG}-${FC_ARCH}"      /usr/local/bin/jailer
    rm -rf "$TMP"
    ok "Firecracker ${FC_TAG} installed"
  fi
fi

# ---------------------------------------------------------------- 4. kvm access
log "Granting KVM access"
if [[ ! -e /dev/kvm ]]; then
  warn "/dev/kvm does not exist — nested virtualization is off."
  warn "Add to C:\\Users\\bhavy\\.wslconfig:  [wsl2]  nestedVirtualization=true"
  warn "then run 'wsl --shutdown' from PowerShell."
else
  if id -nG | tr ' ' '\n' | grep -qx kvm; then
    ok "Already in the kvm group"
  else
    sudo usermod -aG kvm "$USER"
    ok "Added $USER to the kvm group"
    warn "This does NOT apply to your current shell."
    warn "Run 'wsl --shutdown' from PowerShell, then reopen WSL."
  fi
fi

# ---------------------------------------------------------------- 5. verify
log "Verification"
printf '    %-14s %s\n' "docker"      "$(docker --version 2>/dev/null || echo MISSING)"
printf '    %-14s %s\n' "compose"     "$(docker compose version 2>/dev/null | head -1 || echo MISSING)"
printf '    %-14s %s\n' "runsc"       "$(runsc --version 2>/dev/null | head -1 || echo MISSING)"
printf '    %-14s %s\n' "firecracker" "$(firecracker --version 2>/dev/null | head -1 || echo MISSING)"
printf '    %-14s %s\n' "kvm"         "$( [[ -r /dev/kvm && -w /dev/kvm ]] && echo 'accessible' || echo 'NOT accessible until wsl --shutdown')"

cat <<'EOF'

Next:
  1. From PowerShell:   wsl --shutdown       (applies the kvm group + swap)
  2. Reopen WSL, then:  make dev             (core stack, ~384M)
                        make sysinfo         (capture the machine)
                        make mem             (confirm the memory budget)
EOF
