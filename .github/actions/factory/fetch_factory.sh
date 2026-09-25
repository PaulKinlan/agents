#!/usr/bin/env bash
# Fetch the Software Factory at an immutable commit into $1.
#
# Usage: fetch_factory.sh <destination>
# Env:   FACTORY_REF       full 40-character commit SHA (required)
#        FACTORY_REPO_URL  repo URL override, used by tests; defaults to the public repo
#
# The fetch is deliberately credential-free: the calling step blanks GH_TOKEN, GITHUB_TOKEN
# and the model keys, disables prompts, and no credential helper is consulted. A branch or
# tag can move under a consumer, so only a full commit SHA is accepted, and the fetched
# commit is checked against the pin before it is used.
set -euo pipefail

DEST="${1:?usage: fetch_factory.sh <destination>}"
FACTORY_REPO_URL="${FACTORY_REPO_URL:-https://github.com/paulkinlan/agents.git}"
FACTORY_REF="${FACTORY_REF:-}"

if ! [[ "$FACTORY_REF" =~ ^[0-9a-f]{40}$ ]]; then
  echo "error: FACTORY_REF must be a full 40-character commit SHA (got '${FACTORY_REF}')" >&2
  exit 1
fi

echo "Fetching Software Factory at pinned commit $FACTORY_REF"
rm -rf "$DEST"
mkdir -p "$DEST"
git -C "$DEST" init --quiet
git -C "$DEST" remote add origin "$FACTORY_REPO_URL"
git -C "$DEST" -c credential.helper= fetch --depth 1 --quiet origin "$FACTORY_REF"

FETCHED="$(git -C "$DEST" rev-parse FETCH_HEAD)"
if [ "$FETCHED" != "$FACTORY_REF" ]; then
  echo "error: fetched commit $FETCHED does not match the pinned $FACTORY_REF" >&2
  exit 1
fi

git -C "$DEST" checkout --quiet FETCH_HEAD
