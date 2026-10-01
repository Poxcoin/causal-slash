#!/bin/bash
# Setup isolated Git Worktrees for concurrent swarm terminals

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARENT_DIR="$(dirname "$ROOT_DIR")"

echo "[SWARM] Initializing isolated Git Worktrees..."

# Create worktree for Terminal 1 (Core)
if [ ! -d "$PARENT_DIR/causal_term1_core" ]; then
    git worktree add "$PARENT_DIR/causal_term1_core" -b term1_core main
    echo "[OK] Terminal 1 worktree created: $PARENT_DIR/causal_term1_core"
fi

# Create worktree for Terminal 2 (SDK)
if [ ! -d "$PARENT_DIR/causal_term2_sdk" ]; then
    git worktree add "$PARENT_DIR/causal_term2_sdk" -b term2_sdk main
    echo "[OK] Terminal 2 worktree created: $PARENT_DIR/causal_term2_sdk"
fi

# Create worktree for Terminal 3 (Red Team)
if [ ! -d "$PARENT_DIR/causal_term3_redteam" ]; then
    git worktree add "$PARENT_DIR/causal_term3_redteam" -b term3_redteam main
    echo "[OK] Terminal 3 worktree created: $PARENT_DIR/causal_term3_redteam"
fi

# Create worktree for Terminal 5 (Quant / Research)
if [ ! -d "$PARENT_DIR/causal_term5_quant" ]; then
    git worktree add "$PARENT_DIR/causal_term5_quant" -b term5_quant main
    echo "[OK] Terminal 5 worktree created: $PARENT_DIR/causal_term5_quant"
fi

echo "[SWARM] Active worktree list:"
git worktree list
