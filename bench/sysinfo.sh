#!/usr/bin/env bash
# Capture the exact machine a benchmark ran on.
#
# Every result file in bench/results/ embeds the output of this script. A
# latency number without its hardware, kernel, thermal state and concurrent
# load is not evidence — it is an anecdote.
#
# Usage:
#   ./bench/sysinfo.sh            human-readable
#   ./bench/sysinfo.sh --json     machine-readable (embedded into results)

set -uo pipefail

JSON=0
[[ "${1:-}" == "--json" ]] && JSON=1

# ---------------------------------------------------------------- collectors
cpu_model()   { grep -m1 '^model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//'; }
cpu_threads() { nproc; }
cpu_mhz()     { awk '/^cpu MHz/{s+=$4; n++} END{if(n) printf "%.0f", s/n}' /proc/cpuinfo; }
kernel()      { uname -r; }
distro()      { . /etc/os-release 2>/dev/null && echo "$PRETTY_NAME"; }
mem_total()   { awk '/^MemTotal:/{printf "%.0f", $2/1024}' /proc/meminfo; }
mem_avail()   { awk '/^MemAvailable:/{printf "%.0f", $2/1024}' /proc/meminfo; }
swap_total()  { awk '/^SwapTotal:/{printf "%.0f", $2/1024}' /proc/meminfo; }
loadavg()     { cut -d' ' -f1-3 /proc/loadavg; }
uptime_s()    { cut -d' ' -f1 /proc/uptime; }
kvm()         { [[ -e /dev/kvm ]] && { [[ -r /dev/kvm && -w /dev/kvm ]] && echo "present,accessible" || echo "present,permission-denied"; } || echo "absent"; }
virt()        { systemd-detect-virt 2>/dev/null || { grep -qi microsoft /proc/version && echo "wsl2" || echo "unknown"; }; }

# Thermal state matters on a 15W laptop part: a long benchmark measures a
# slower machine than a short one. Report it so the reader can judge.
pkg_temp() {
  local t
  for z in /sys/class/thermal/thermal_zone*/temp; do
    [[ -r "$z" ]] || continue
    t=$(cat "$z" 2>/dev/null) || continue
    [[ "$t" =~ ^[0-9]+$ ]] && { awk -v v="$t" 'BEGIN{printf "%.1f", v/1000}'; return; }
  done
  echo "unavailable"
}

# What else was competing for the machine. A benchmark run with Chrome open is
# a different experiment from one run on an idle box.
containers() {
  command -v docker >/dev/null 2>&1 || { echo "docker-not-installed"; return; }
  docker ps --format '{{.Names}}:{{.Image}}' 2>/dev/null | paste -sd',' - || echo "none"
}
container_mem() {
  command -v docker >/dev/null 2>&1 || { echo "0"; return; }
  docker stats --no-stream --format '{{.MemUsage}}' 2>/dev/null \
    | awk -F'/' '{gsub(/[^0-9.]/,"",$1); s+=$1} END{printf "%.0f", s+0}'
}

tool_version() {
  command -v "$1" >/dev/null 2>&1 && { "$@" 2>&1 | head -1; } || echo "not-installed"
}

# ---------------------------------------------------------------- emit
if [[ $JSON -eq 1 ]]; then
  cat <<EOF
{
  "captured_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "cpu": {
    "model": "$(cpu_model)",
    "threads": $(cpu_threads),
    "avg_mhz_at_capture": $(cpu_mhz),
    "package_temp_c": "$(pkg_temp)"
  },
  "memory": {
    "total_mb": $(mem_total),
    "available_mb": $(mem_avail),
    "swap_total_mb": $(swap_total),
    "docker_containers_mb": $(container_mem)
  },
  "os": {
    "distro": "$(distro)",
    "kernel": "$(kernel)",
    "virtualization": "$(virt)"
  },
  "virt": { "kvm": "$(kvm)" },
  "load": { "avg_1_5_15": "$(loadavg)", "uptime_s": $(uptime_s) },
  "concurrent_containers": "$(containers)",
  "toolchain": {
    "go": "$(tool_version go version)",
    "rustc": "$(tool_version rustc --version)",
    "docker": "$(tool_version docker --version)",
    "runsc": "$(tool_version runsc --version)",
    "firecracker": "$(tool_version firecracker --version)"
  }
}
EOF
else
  cat <<EOF
Airlock benchmark environment
captured  $(date -u +%Y-%m-%dT%H:%M:%SZ)

CPU       $(cpu_model)
          $(cpu_threads) threads, ~$(cpu_mhz) MHz avg at capture, package $(pkg_temp) C
Memory    $(mem_total) MB total, $(mem_avail) MB available, $(swap_total) MB swap
          $(container_mem) MB currently held by docker containers
OS        $(distro)
          kernel $(kernel), virtualization: $(virt)
KVM       $(kvm)
Load      $(loadavg) (1/5/15 min), up $(uptime_s)s

Concurrent containers
          $(containers)

Toolchain
  go            $(tool_version go version)
  rustc         $(tool_version rustc --version)
  docker        $(tool_version docker --version)
  runsc         $(tool_version runsc --version)
  firecracker   $(tool_version firecracker --version)

NOTE  This is a laptop under a hypervisor (WSL2), with a hybrid P-core/E-core
      CPU and no thermal headroom guarantee. Absolute latencies are upper
      bounds and absolute throughput is a lower bound relative to bare metal.
      Cross-arm comparisons remain valid: all arms pay the same tax.
      See docs/BENCHMARK.md section 5, "Threats to validity".
EOF
fi
