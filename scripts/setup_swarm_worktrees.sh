#!/bin/bash
# Setup isolated Git Worktrees for concurrent swarm terminals

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARENT_DIR="$(dirname "$ROOT_DIR")"

echo "[SWARM] Initializing isolated Git Worktrees..."

# Create worktree for Track 1 (Blue Team Core)
if [ ! -d "$PARENT_DIR/csls_blueteam" ]; then
    git worktree add "$PARENT_DIR/csls_blueteam" -b csls_blueteam main
    echo "[OK] Track 1 worktree created: $PARENT_DIR/csls_blueteam"
fi

# Create worktree for Track 2 (Terminal & SDK)
if [ ! -d "$PARENT_DIR/csls_terminal" ]; then
    git worktree add "$PARENT_DIR/csls_terminal" -b csls_terminal main
    echo "[OK] Track 2 worktree created: $PARENT_DIR/csls_terminal"
fi

# Create worktree for Track 3 (Red Team)
if [ ! -d "$PARENT_DIR/csls_redteam" ]; then
    git worktree add "$PARENT_DIR/csls_redteam" -b csls_redteam main
    echo "[OK] Track 3 worktree created: $PARENT_DIR/csls_redteam"
fi

# Create worktree for Track 4 (Marketing & GPU Partners)
if [ ! -d "$PARENT_DIR/csls_marketing" ]; then
    git worktree add "$PARENT_DIR/csls_marketing" -b csls_marketing main
    echo "[OK] Track 4 worktree created: $PARENT_DIR/csls_marketing"
fi

echo "[SWARM] Active worktree list:"
git worktree list
