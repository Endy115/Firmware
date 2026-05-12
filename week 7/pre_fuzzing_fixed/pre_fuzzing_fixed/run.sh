#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat <<'USAGE'
Usage:
  Pre_Fuzzing/run.sh <target_binary> [export_root]

Arguments:
  target_binary   Path to firmware binary for IDA processing
  export_root     Optional. If omitted, defaults to:
                  <dirname(target_binary)>/export-for-ai-<basename(target_binary)>

Environment variables:
  IDAT_BIN                Path to idat/idat64
  PYTHON_BIN              Python interpreter (default: python3, fallback: python)

  ENABLE_LLM_EXTRACT      1 = run llm_extract_api_params.py (default: 1)
  LLM_STRICT              1 = fail if LLM env is incomplete (default: 0)
  AG_BASE_URL             LLM base URL (Antigravity/OpenAI-compatible)
  AG_MODEL                LLM model
  Private_API_KEY         LLM API key

  DISTANCE_OFFLOAD        1 = run Distance.py on remote server (default: 0)
  DISTANCE_REMOTE_HOST    SSH host alias or user@host
  DISTANCE_REMOTE_BASE    Remote jobs dir (default: ~/firmagent_jobs)
  DISTANCE_REMOTE_PYTHON  Remote python interpreter (default: python3)

Examples:
  Pre_Fuzzing/run.sh /path/to/httpd

  AG_BASE_URL=https://your-antigravity-endpoint/v1 \
  AG_MODEL=your-model \
  Private_API_KEY=xxxx \
  Pre_Fuzzing/run.sh /path/to/httpd

  DISTANCE_OFFLOAD=1 \
  DISTANCE_REMOTE_HOST=user@server \
  Pre_Fuzzing/run.sh /path/to/httpd
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 1 ]]; then
  usage
  exit 0
fi

TARGET_BINARY="$1"
if [[ ! -f "$TARGET_BINARY" ]]; then
  echo "[-] target binary not found: $TARGET_BINARY" >&2
  exit 1
fi

TARGET_BINARY="$(cd -- "$(dirname -- "$TARGET_BINARY")" && pwd)/$(basename -- "$TARGET_BINARY")"

BINARY_DIR="$(dirname -- "$TARGET_BINARY")"
BINARY_BASE="$(basename -- "$TARGET_BINARY")"
DEFAULT_EXPORT_ROOT="$BINARY_DIR/export-for-ai-$BINARY_BASE"
EXPORT_ROOT="${2:-$DEFAULT_EXPORT_ROOT}"

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="${PYTHON_BIN:-python3}"
else
  PYTHON_BIN="${PYTHON_BIN:-python}"
fi

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[-] python not found: $PYTHON_BIN" >&2
  exit 1
fi

IDAT_BIN="${IDAT_BIN:-${idat:-idat}}"
if ! command -v "$IDAT_BIN" >/dev/null 2>&1; then
  echo "[-] idat not found: $IDAT_BIN" >&2
  echo "    Set IDAT_BIN=/path/to/idat64 or ensure idat is on PATH." >&2
  exit 1
fi

ENABLE_LLM_EXTRACT="${ENABLE_LLM_EXTRACT:-1}"
LLM_STRICT="${LLM_STRICT:-0}"
AG_BASE_URL="${AG_BASE_URL:-}"
AG_MODEL="${AG_MODEL:-}"
Private_API_KEY="${Private_API_KEY:-}"

DISTANCE_OFFLOAD="${DISTANCE_OFFLOAD:-0}"
DISTANCE_REMOTE_HOST="${DISTANCE_REMOTE_HOST:-}"
DISTANCE_REMOTE_BASE="${DISTANCE_REMOTE_BASE:-~/firmagent_jobs}"
DISTANCE_REMOTE_PYTHON="${DISTANCE_REMOTE_PYTHON:-python3}"

cd "$REPO_ROOT"

run_step() {
  local name="$1"
  shift
  echo ""
  echo "========== $name =========="
  "$@"
  echo "[+] Done: $name"
}

offload_distance() {
  local binary_dir="$1"
  local binary_base="$2"

  if [[ -z "$DISTANCE_REMOTE_HOST" ]]; then
    echo "[-] DISTANCE_REMOTE_HOST is required when DISTANCE_OFFLOAD=1" >&2
    exit 1
  fi

  local ts job_name work_root job_dir remote_job_dir
  ts="$(date +%Y%m%d_%H%M%S)"
  job_name="JOB_${binary_base}_${ts}"
  work_root="$HOME/distance_jobs"
  job_dir="$work_root/$job_name"
  remote_job_dir="${DISTANCE_REMOTE_BASE%/}/$job_name"

  mkdir -p "$job_dir"

  cp "$binary_dir/sink_scope_addr.txt" "$job_dir/"
  cp "$SCRIPT_DIR/Distance.py" "$job_dir/"

  echo "[*] Preparing remote distance job: $job_name"
  ls -l "$job_dir"

  echo "[*] Creating remote base dir..."
  ssh "$DISTANCE_REMOTE_HOST" "mkdir -p ${DISTANCE_REMOTE_BASE}"

  echo "[*] Uploading Distance.py and sink_scope_addr.txt..."
  scp -r "$job_dir" "$DISTANCE_REMOTE_HOST:$DISTANCE_REMOTE_BASE/"

  echo "[*] Running remote Distance.py..."
  ssh "$DISTANCE_REMOTE_HOST" \
    "$DISTANCE_REMOTE_PYTHON $remote_job_dir/Distance.py \
      --sink-scope $remote_job_dir/sink_scope_addr.txt \
      --output-dir $remote_job_dir \
      > $remote_job_dir/distance_run.log 2>&1"

  echo "[*] Downloading output back..."
  scp "$DISTANCE_REMOTE_HOST:$remote_job_dir/sink_distance_scores.json" "$binary_dir/"
  scp "$DISTANCE_REMOTE_HOST:$remote_job_dir/sink_distance_scores.csv" "$binary_dir/"
  scp "$DISTANCE_REMOTE_HOST:$remote_job_dir/distance_run.log" "$binary_dir/" || true

  echo "[+] Remote distance completed: $binary_dir/sink_distance_scores.json"
}

# 1) 获取反编译
run_step "get decompilation with IDA Pro..." \
  "$IDAT_BIN" -A -Lida_decompile.log -S"$SCRIPT_DIR/decompile.py" "$TARGET_BINARY"

# 2) API & 参数提取
if [[ "$ENABLE_LLM_EXTRACT" == "1" ]]; then
  if [[ -z "$AG_BASE_URL" || -z "$AG_MODEL" || -z "$Private_API_KEY" ]]; then
    echo "[-] ENABLE_LLM_EXTRACT=1 but AG_BASE_URL / AG_MODEL / Private_API_KEY is missing." >&2
    if [[ "$LLM_STRICT" == "1" ]]; then
      exit 1
    else
      echo "[!] Continue without LLM extraction because LLM_STRICT=0"
    fi
  else
    run_step "extract API and parameters with LLM..." \
      "$PYTHON_BIN" "$SCRIPT_DIR/llm_extract_api_params.py" \
        --input "$EXPORT_ROOT" \
        --output "$BINARY_DIR/Pre_fuzzing.json" \
        --base-url "$AG_BASE_URL" \
        --model "$AG_MODEL" \
        --api-key "$Private_API_KEY" \
        --token-limit 100000 \
        --show-llm-output \
        --llm-output-dir "$BINARY_DIR/llm_raw"
  fi
else
  echo ""
  echo "[!] Skipping LLM API/parameter extraction because ENABLE_LLM_EXTRACT=0"
fi

# 3) 地址范围提取
run_step "地址范围提取(Get_SinkFunc.py)" \
  "$IDAT_BIN" -A -Lida_sinks.log -S"$SCRIPT_DIR/Get_SinkFunc.py" "$TARGET_BINARY"

# 4) 距离计算
if [[ "$DISTANCE_OFFLOAD" == "1" ]]; then
  echo ""
  echo "========== 距离计算(Distance.py remote offload) =========="
  offload_distance "$BINARY_DIR" "$BINARY_BASE"
  echo "[+] Done: 距离计算(Distance.py remote offload)"
else
  run_step "距离计算(Distance.py)" \
    "$PYTHON_BIN" "$SCRIPT_DIR/Distance.py" \
      --sink-scope "$BINARY_DIR/sink_scope_addr.txt" \
      --output-dir "$BINARY_DIR"
fi

echo ""
echo "[+] Pre-fuzzing pipeline finished."
