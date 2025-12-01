#!/usr/bin/env bash

set -euo pipefail

# Install build dependencies required for native extensions.
if command -v yum >/dev/null 2>&1; then
  yum install -y git openssl-devel
fi

# Configure git to use the provided GitHub token for private repositories.
# Note: run from a neutral directory to avoid touching a submodule worktree
# that points to a non-existent superproject .git inside the container.
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  if command -v git >/dev/null 2>&1; then
    (
      cd / || cd /tmp || true
      git config --global url."https://oauth2:${GITHUB_TOKEN}@github.com/".insteadOf https://github.com/
    )
  else
    echo "[WARN] git is not available; cannot preconfigure token for GitHub clones." >&2
  fi
else
  echo "[WARN] GITHUB_TOKEN not set; private dependencies may fail to download." >&2
fi
