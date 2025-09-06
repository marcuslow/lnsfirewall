#!/bin/sh
# pfSense/FreeBSD environment check for Python + psutil
# Purpose: Run unattended and print clear results about Python version, pip, and psutil availability/installation.
# Safe: This script does NOT install anything. It only queries and prints.
# Usage: sh check_psutil_env.sh > psutil_env_report.txt 2>&1

# Do not set -e; we want to continue even if some checks fail

say() { printf "%s\n" "$*"; }
hr() { say "------------------------------------------------------------"; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# 1) Basic system info
hr
say "[INFO] Starting Python/psutil environment checks"
DATE_NOW=$(date 2>/dev/null || true)
say "[INFO] Date: $DATE_NOW"
UNAME=$(uname -a 2>/dev/null || true)
say "[INFO] System: $UNAME"
hr

# 2) pkg presence
if have_cmd pkg; then
  say "[OK] pkg is available"
  PKG_VER=$(pkg -v 2>/dev/null || true)
  say "[INFO] pkg version: $PKG_VER"
else
  say "[WARN] pkg is NOT available on this system"
fi
hr

# 3) Detect best Python interpreter (prefer 3.11, then 3.10, then 3.9, then python3)
BEST_PY=""
BEST_TAG=""
for CAND in python3.11 python3.10 python3.9 python3; do
  if have_cmd "$CAND"; then
    BEST_PY="$CAND"
    case "$CAND" in
      python3.11) BEST_TAG="py311" ;;
      python3.10) BEST_TAG="py310" ;;
      python3.9)  BEST_TAG="py39"  ;;
      *) BEST_TAG="py$("$CAND" -c 'import sys; print(f"{sys.version_info.major}{sys.version_info.minor}")' 2>/dev/null || echo 39)" ;;
    esac
    break
  fi
done

if [ -n "$BEST_PY" ]; then
  say "[OK] Found Python interpreter: $BEST_PY (tag: $BEST_TAG)"
  PY_VER_STR=$($BEST_PY -V 2>&1 || true)
  say "[INFO] $PY_VER_STR"
else
  say "[FAIL] No suitable Python interpreter (python3.x) found"
fi
hr

# 4) pip for chosen interpreter
if [ -n "$BEST_PY" ]; then
  if "$BEST_PY" -m pip --version >/dev/null 2>&1; then
    PIP_VER=$($BEST_PY -m pip --version 2>/dev/null || true)
    say "[OK] pip present for $BEST_PY: $PIP_VER"
  else
    say "[WARN] pip is NOT available for $BEST_PY"
  fi
fi
hr

# 5) Check psutil import with chosen interpreter
if [ -n "$BEST_PY" ]; then
  if "$BEST_PY" -c "import psutil, sys; print('OK psutil', psutil.__version__)" >/dev/null 2>&1; then
    PSUTIL_VER=$($BEST_PY -c "import psutil; print(psutil.__version__)" 2>/dev/null || true)
    say "[OK] psutil is importable with $BEST_PY (version: $PSUTIL_VER)"
  else
    say "[INFO] psutil is NOT importable with $BEST_PY"
  fi
fi
hr

# 6) Check if psutil pkg is installed (any version) and specifically matching BEST_TAG
if have_cmd pkg; then
  say "[INFO] Installed psutil packages (any Python):"
  pkg info | grep -E 'py3[0-9]+-psutil' || say "(none)"

  if [ -n "$BEST_TAG" ]; then
    MATCH_PKG="${BEST_TAG}-psutil"
    if pkg info -E "$MATCH_PKG" >/dev/null 2>&1; then
      say "[OK] Installed matching psutil package: $MATCH_PKG"
    else
      say "[INFO] No installed matching psutil package for $BEST_TAG"
    fi
  fi
else
  say "[WARN] Skipping pkg-installed checks (pkg not available)"
fi
hr

# 7) Check repository availability for psutil (dry-run)
if have_cmd pkg; then
  say "[INFO] Repository availability for psutil packages:"
  say "- Listing any psutil packages in repo:"
  pkg search -x '^py3[0-9]+-psutil$' 2>/dev/null || say "(none found or repo offline)"

  if [ -n "$BEST_TAG" ]; then
    MATCH_PKG="${BEST_TAG}-psutil"
    say "- Dry-run install check for $MATCH_PKG:"
    if pkg install -n "$MATCH_PKG" >/dev/null 2>&1; then
      say "[OK] $MATCH_PKG appears AVAILABLE in the repo"
    else
      say "[INFO] $MATCH_PKG does NOT appear available (or repo offline)"
    fi
  fi
else
  say "[WARN] Skipping repo checks (pkg not available)"
fi
hr

# 8) Guidance
say "GUIDANCE:"
if [ -n "$BEST_PY" ]; then
  if "$BEST_PY" -c "import psutil" >/dev/null 2>&1; then
    say "- psutil import already works with $BEST_PY; you are good to go."
  else
    if have_cmd pkg; then
      say "- To install psutil for $BEST_PY: pkg install ${BEST_TAG}-psutil (if available)."
      say "- If ${BEST_TAG}-psutil is not available, see which versions exist with: pkg search -x '^py3[0-9]+-psutil$'"
      say "- Optionally use a different Python version that matches an available psutil pkg (e.g., py39-psutil with python3.9)."
    else
      say "- pkg tool not found; cannot check/install OS psutil package."
    fi
  fi
else
  say "- Install a Python 3 interpreter (python3.11, 3.10, or 3.9) and re-run this script."
fi
hr

say "[DONE] Environment checks complete."
exit 0

