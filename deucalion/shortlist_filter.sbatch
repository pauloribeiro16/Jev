#!/bin/bash
#SBATCH -J jevshortlist
#SBATCH -A f202512235cpcaa1g
#SBATCH -p dev-a100-40
#SBATCH -q normal
#SBATCH --gres=gpu:a100:1
#SBATCH --time=04:00:00
#SBATCH -o /projects/F202512235CPCAA1/CyberMetric_Deucalion/jevlogs/shortlist-%j.out
#SBATCH -e /projects/F202512235CPCAA1/CyberMetric_Deucalion/jevlogs/shortlist-%j.err

# Runs the Jev shortlist filter on the big model, then syncs results back.
# Submit:  sbatch deucalion/shortlist_filter.sbatch
#
# Design notes, all from failures already paid for:
#  * Ollama must be 0.32.13 for qwen3.8:27b — the 0.31.1 binary in PATH rejects
#    it with "unknown model architecture".
#  * PORT is derived from the job id; two jobs on one node collide on 11434.
#  * `set +u` around profile/module: Deucalion's profile.d expands unset vars
#    and kills non-interactive bash with no error message.
#  * Bytecode is wiped and disabled before python, or a stale .pyc from a
#    previous sync aborts the job with a confusing ImportError.
#  * Strictly sequential model calls — parallel ones return Connection refused.

set -euo pipefail

PROJ=/projects/F202512235CPCAA1/CyberMetric_Deucalion/jev-phase3
BD=/projects/F202512235CPCAA1/CyberMetric_Deucalion
GRAPHIFY=/projects/F202512235CPCAA1/graphify-methodology
MODEL="${MODEL:-qwen3.8:27b}"

mkdir -p "$BD/jevlogs"
RUN_LOG="$BD/jevlogs/shortlist-${SLURM_JOB_ID}.log"
exec > >(tee -a "$RUN_LOG") 2>&1

echo "=== jev shortlist filter ==="
echo "JOB=$SLURM_JOB_ID NODE=$(hostname) MODEL=$MODEL"
date -u +"START=%Y-%m-%dT%H:%M:%SZ"

# ---- Ollama 0.32.13 (required for qwen3.8) -------------------------------
export PATH="${GRAPHIFY}/bin:${PATH}"
export LD_LIBRARY_PATH="${GRAPHIFY}/lib/ollama:${LD_LIBRARY_PATH:-}"
export OLLAMA_MODELS="${BD}/ollama_data/models"
export PORT=$((11434 + SLURM_JOB_ID % 20000))
export OLLAMA_HOST="127.0.0.1:${PORT}"
OLLAMA_BASE="http://127.0.0.1:${PORT}"
echo "OLLAMA_BASE=$OLLAMA_BASE"

ollama --version 2>&1 | head -2 || true

ollama serve &
OLLAMA_PID=$!
trap 'echo "EXIT=$? JOB=$SLURM_JOB_ID"; kill $OLLAMA_PID 2>/dev/null || true' EXIT

for i in $(seq 1 30); do
    if curl -s "${OLLAMA_BASE}/v1/models" >/dev/null 2>&1; then
        echo "ollama up after ${i}0s"
        break
    fi
    sleep 10
done
if ! curl -s "${OLLAMA_BASE}/v1/models" >/dev/null 2>&1; then
    echo "FATAL: ollama never came up"
    exit 1
fi

# ---- python, with stale bytecode purged ----------------------------------
export PYTHONDONTWRITEBYTECODE=1
find "$PROJ/scripts" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find "$PROJ/scripts" -name "*.pyc" -delete 2>/dev/null || true

cd "$PROJ"
python3 scripts/run_shortlist_filter.py \
    --prompts "$PROJ/prompts" \
    --out "$PROJ/data/shortlists" \
    --model "$MODEL" \
    --base-url "$OLLAMA_BASE"
STATUS=$?

date -u +"END=%Y-%m-%dT%H:%M:%SZ"
wc -l "$PROJ"/data/shortlists/*.jsonl 2>/dev/null || true
echo "STATUS=$STATUS"
exit $STATUS