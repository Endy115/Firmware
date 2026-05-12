#!/usr/bin/env python3
import argparse
import ast
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests

DEFAULT_BASE_URL = os.getenv("AG_BASE_URL", "https://api.deepseek.com")
DEFAULT_MODEL = os.getenv("AG_MODEL", "deepseek-chat")
DEFAULT_PROMPT = (
    "我需要对固件进行fuzzing。"
    "请只提取两类信息："
    "1) 可直接用于HTTP请求的相对API路径，例如 /apply.cgi, /login.cgi, /HNAP1/;"
    "2) 可能接收外部输入的参数名。"
    "不要返回函数名、sub_xxx符号名、普通文件路径、/proc路径、资源文件名、结构体成员名。"
    "输出必须是JSON，格式为"
    "{\"api_endpoints\":[...],\"para\":[...]}。"
)

HTTP_ROUTE_HINTS = (
    ".cgi", ".asp", ".xml", ".txt", ".php", ".do", ".action"
)


def _estimate_tokens_by_chars(text: str, avg_chars_per_token: float) -> int:
    if avg_chars_per_token <= 0:
        return len(text)
    return int(len(text) / avg_chars_per_token)


def _conservative_chunk_chars(token_limit: int, reserved_tokens: int, avg_chars_per_token: float) -> int:
    usable_tokens = max(0, token_limit - reserved_tokens)
    return max(64, int(usable_tokens * avg_chars_per_token * 0.8))


def read_input_text(file_path: Path) -> str:
    return file_path.read_text(encoding="utf-8", errors="ignore")


def select_input_files(input_path: Path) -> List[Path]:
    if input_path.is_file():
        return [input_path]

    if not input_path.is_dir():
        return []

    selected: List[Path] = []
    priority_files = ["all_decompiled.c", "strings.txt"]
    for name in priority_files:
        p = input_path / name
        if p.exists() and p.is_file():
            selected.append(p)

    dedup: List[Path] = []
    seen = set()
    for p in selected:
        key = str(p.resolve())
        if key not in seen:
            seen.add(key)
            dedup.append(p)
    return dedup


def build_chunks(file_path: Path, text: str, max_chars: int, overlap_chars: int) -> List[Dict[str, Any]]:
    if max_chars <= 0:
        raise ValueError("max_chars must be > 0")
    if overlap_chars < 0:
        raise ValueError("overlap_chars must be >= 0")
    if overlap_chars >= max_chars:
        raise ValueError("overlap_chars must be < max_chars")

    size = len(text)
    if size == 0:
        return [{
            "file": str(file_path),
            "chunk_index": 1,
            "chunk_total": 1,
            "start": 0,
            "end": 0,
            "text": "",
        }]

    chunks: List[Dict[str, Any]] = []
    step = max_chars - overlap_chars
    start = 0
    while start < size:
        end = min(size, start + max_chars)
        chunks.append({
            "file": str(file_path),
            "start": start,
            "end": end,
            "text": text[start:end],
        })
        if end >= size:
            break
        start += step

    total = len(chunks)
    for idx, c in enumerate(chunks, 1):
        c["chunk_index"] = idx
        c["chunk_total"] = total
    return chunks


def build_messages(prompt: str, chunk: Dict[str, Any]) -> list:
    system_msg = (
        "你是固件安全分析助手。"
        "请仅输出合法JSON，不要输出解释、不要输出Markdown。"
        "JSON格式必须为: {\"api_endpoints\":[\"api1\",\"api2\"],\"para\":[\"para1\",\"para2\"]}。"
        "api_endpoints与para都必须是数组。"
        "数组中的每个元素必须是字符串。"
        "如果无法完全确定，请只输出最可能的候选。"
    )
    file_info = (
        f"[SOURCE_FILE]: {chunk['file']}\n"
        f"[CHUNK]: {chunk['chunk_index']}/{chunk['chunk_total']}\n"
        f"[RANGE]: {chunk['start']}..{chunk['end']}"
    )
    user_msg = (
        f"{prompt}\n\n"
        "请严格返回JSON，且顶层字段必须是 api_endpoints 和 para。\n\n"
        f"{file_info}\n\n"
        "以下是待分析文件内容:\n"
        f"{chunk['text']}"
    )
    return [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": user_msg},
    ]


def normalize_base_url(base_url: str) -> str:
    if not base_url:
        raise ValueError("AG_BASE_URL is not set")
    base = base_url.rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    return f"{base}/chat/completions"


def call_llm(
    base_url: str,
    api_key: str,
    model: str,
    messages: list,
    timeout: int,
    temperature: float,
) -> str:
    url = normalize_base_url(base_url)
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "response_format": {"type": "json_object"},
    }

    resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()

    choices = data.get("choices", [])
    if not choices:
        raise ValueError(f"API response missing choices: {data}")

    message = choices[0].get("message", {})
    content = message.get("content", "")
    if not content:
        raise ValueError(f"API response missing message.content: {data}")

    return content


def parse_json_from_text(text: str) -> dict:
    raw = text.strip()
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    fenced = re.search(r"```(?:json)?\s*(\{[\s\S]*\})\s*```", raw, flags=re.IGNORECASE)
    if fenced:
        return json.loads(fenced.group(1))

    first = raw.find("{")
    last = raw.rfind("}")
    if first != -1 and last != -1 and last > first:
        candidate = raw[first:last + 1]
        try:
            return json.loads(candidate)
        except Exception:
            pass

    for i, ch in enumerate(raw):
        if ch != "{":
            continue
        depth = 0
        in_str = False
        esc = False
        for j in range(i, len(raw)):
            c = raw[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
                continue
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    candidate = raw[i:j + 1]
                    try:
                        obj = json.loads(candidate)
                        if isinstance(obj, dict):
                            return obj
                    except Exception:
                        break

    try:
        py_obj = ast.literal_eval(raw)
        if isinstance(py_obj, dict):
            return py_obj
    except Exception:
        pass

    if first != -1 and last != -1 and last > first:
        candidate = raw[first:last + 1]
        try:
            py_obj = ast.literal_eval(candidate)
            if isinstance(py_obj, dict):
                return py_obj
        except Exception:
            pass

    raise ValueError("unable to parse JSON from LLM output")


def _extract_text_from_item(item: Any, preferred_keys: List[str]) -> str:
    if isinstance(item, str):
        return item.strip()
    if isinstance(item, (int, float, bool)):
        return str(item)
    if isinstance(item, dict):
        for key in preferred_keys:
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        for value in item.values():
            if isinstance(value, str) and value.strip():
                return value.strip()
        return json.dumps(item, ensure_ascii=False, sort_keys=True)
    return ""


def normalize_schema(obj: dict) -> Dict[str, List[str]]:
    api_endpoints = obj.get("api_endpoints", [])
    para = obj.get("para", [])

    if not isinstance(api_endpoints, list):
        api_endpoints = [api_endpoints]
    if not isinstance(para, list):
        para = [para]

    normalized_api: List[str] = []
    normalized_para: List[str] = []

    for item in api_endpoints:
        value = _extract_text_from_item(item, ["path", "url", "endpoint", "api", "name", "value"])
        if value:
            normalized_api.append(value)

    for item in para:
        value = _extract_text_from_item(item, ["name", "param", "parameter", "key", "field", "value"])
        if value:
            normalized_para.append(value)

    return {
        "api_endpoints": normalized_api,
        "para": normalized_para,
    }


def _dedup_strings(items: Iterable[str]) -> List[str]:
    result: List[str] = []
    seen = set()
    for item in items:
        key = item.strip()
        if not key:
            continue
        if key in seen:
            continue
        seen.add(key)
        result.append(key)
    return result


def _normalize_endpoint(value: str) -> str:
    s = value.strip().strip('"').strip("'")
    s = s.replace("\\/", "/")
    if s.startswith("goform/"):
        s = "/" + s
    return s


def _looks_like_http_endpoint(value: str) -> bool:
    s = _normalize_endpoint(value)
    if not s:
        return False

    bad_prefixes = (
        "sub_",
        "return_",
        "create_",
        "do_",
        "get_",
        "set_",
        "/proc/",
        "/sys/",
        "/dev/",
        "/www/",
    )
    if s.startswith(bad_prefixes):
        return False

    bad_exact = {
        "messages.txt",
        "config.bin",
        "auth.bmp",
        "tun6to4",
        "ej_handlers",
    }
    if s in bad_exact:
        return False

    if s.startswith("/"):
        if s.upper().startswith("/HNAP1"):
            return True
        if "/" in s[1:] or any(ext in s.lower() for ext in HTTP_ROUTE_HINTS):
            return True
        return False

    if s.startswith("goform/"):
        return True

    return False


def sanitize_api_endpoints(items: Iterable[str]) -> List[str]:
    result: List[str] = []
    seen = set()
    for item in items:
        s = _normalize_endpoint(item)
        if not _looks_like_http_endpoint(s):
            continue
        if s not in seen:
            seen.add(s)
            result.append(s)
    return result


def _looks_like_param_name(value: str) -> bool:
    s = value.strip()
    if not s:
        return False

    if s.startswith(("sub_", "return_", "create_")):
        return False

    if re.fullmatch(r"[av]\d+", s):
        return False

    if "/" in s:
        return False

    if s.endswith((".cgi", ".asp", ".xml", ".txt", ".bmp", ".bin")):
        return False

    return True


def sanitize_params(items: Iterable[str]) -> List[str]:
    result: List[str] = []
    seen = set()
    for item in items:
        s = item.strip()
        if not _looks_like_param_name(s):
            continue
        if s not in seen:
            seen.add(s)
            result.append(s)
    return result


def merge_results(parts: List[Dict[str, List[str]]]) -> Dict[str, List[str]]:
    all_api: List[str] = []
    all_para: List[str] = []
    for p in parts:
        all_api.extend(p.get("api_endpoints", []))
        all_para.extend(p.get("para", []))
    return {
        "api_endpoints": sanitize_api_endpoints(_dedup_strings(all_api)),
        "para": sanitize_params(_dedup_strings(all_para)),
    }


def run_extraction(
    files: List[Path],
    base_url: str,
    api_key: str,
    model: str,
    prompt: str,
    timeout: int,
    temperature: float,
    max_chars: int,
    overlap_chars: int,
    max_requests: int,
    token_limit: int,
    avg_chars_per_token: float,
    reserved_tokens: int,
    max_retries: int,
    show_llm_output: bool,
    llm_output_dir: str,
    llm_output_max_chars: int,
) -> Dict[str, List[str]]:
    partial_results: List[Dict[str, List[str]]] = []
    request_count = 0

    output_dir_path = Path(llm_output_dir).resolve() if llm_output_dir else None
    if output_dir_path is not None:
        output_dir_path.mkdir(parents=True, exist_ok=True)

    for file_path in files:
        text = read_input_text(file_path)
        chunks = build_chunks(file_path, text, max_chars=max_chars, overlap_chars=overlap_chars)

        for chunk in chunks:
            if max_requests > 0 and request_count >= max_requests:
                break

            request_count += 1
            try:
                chunk_text = chunk["text"]

                if token_limit > 0:
                    hard_chars = _conservative_chunk_chars(token_limit, reserved_tokens, avg_chars_per_token)
                    if len(chunk_text) > hard_chars:
                        chunk_text = chunk_text[:hard_chars]

                chunk_for_prompt = dict(chunk)
                chunk_for_prompt["text"] = chunk_text

                messages = build_messages(prompt, chunk_for_prompt)

                if token_limit > 0:
                    estimated_input_tokens = 0
                    for msg in messages:
                        estimated_input_tokens += _estimate_tokens_by_chars(
                            msg.get("content", ""),
                            avg_chars_per_token,
                        )

                    if estimated_input_tokens >= token_limit:
                        reduce_ratio = (token_limit - reserved_tokens) / max(1, estimated_input_tokens)
                        reduce_ratio = max(0.2, min(0.95, reduce_ratio))
                        new_len = max(64, int(len(chunk_text) * reduce_ratio))
                        chunk_for_prompt["text"] = chunk_text[:new_len]

                messages = build_messages(prompt, chunk_for_prompt)

                last_exc: Optional[Exception] = None
                parsed: Optional[Dict[str, Any]] = None
                llm_text = ""
                retry_total = max(0, max_retries)

                for attempt in range(0, retry_total + 1):
                    llm_text = call_llm(
                        base_url=base_url,
                        api_key=api_key,
                        model=model,
                        messages=messages,
                        timeout=timeout,
                        temperature=temperature,
                    )

                    if show_llm_output:
                        preview = llm_text[:max(0, llm_output_max_chars)]
                        print(
                            f"[LLM][{file_path.name}][chunk {chunk['chunk_index']}/{chunk['chunk_total']}]"
                            f"[attempt {attempt + 1}] len={len(llm_text)}\n{preview}\n{'-' * 80}"
                        )

                    if output_dir_path is not None:
                        out_file = output_dir_path / (
                            f"{file_path.name}.chunk{chunk['chunk_index']:03d}.attempt{attempt + 1}.txt"
                        )
                        out_file.write_text(llm_text, encoding="utf-8", errors="ignore")

                    try:
                        parsed = parse_json_from_text(llm_text)
                        break
                    except Exception as exc:
                        last_exc = exc
                        if attempt >= retry_total:
                            break
                        repair_user = {
                            "role": "user",
                            "content": (
                                "你上一次返回不是合法JSON。请仅输出合法JSON对象，"
                                "格式必须是 {\"api_endpoints\":[...],\"para\":[...]}，"
                                "数组元素必须是字符串，不要输出任何解释。"
                            ),
                        }
                        messages = messages + [
                            {"role": "assistant", "content": llm_text},
                            repair_user,
                        ]

                if parsed is None:
                    raise last_exc if last_exc is not None else ValueError("unable to parse JSON from LLM output")

                normalized = normalize_schema(parsed)
                partial_results.append(normalized)

            except Exception as exc:
                print(
                    f"[-] chunk failed: file={file_path}, "
                    f"chunk={chunk['chunk_index']}/{chunk['chunk_total']}, error={exc}",
                    file=sys.stderr,
                )
                raise

        if max_requests > 0 and request_count >= max_requests:
            break

    merged = merge_results(partial_results)
    print(f"[+] requests completed: {request_count}")
    return merged


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Use LLM API to extract API endpoints and parameters from file or export directory."
    )
    parser.add_argument("--input", required=True, help="input file or export-for-ai directory")
    parser.add_argument("--output", required=True, help="output JSON file path")
    parser.add_argument(
        "--api-key",
        default=os.getenv("Private_API_KEY", ""),
        help="API key (default: env Private_API_KEY)",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="LLM API base URL (default: env AG_BASE_URL or DeepSeek endpoint)",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help="model name (default: env AG_MODEL or deepseek-chat)",
    )
    parser.add_argument("--prompt", default=DEFAULT_PROMPT, help="analysis prompt")
    parser.add_argument("--max-chars", type=int, default=32000, help="max chars per chunk")
    parser.add_argument("--overlap-chars", type=int, default=1000, help="overlap chars between chunks")
    parser.add_argument("--token-limit", type=int, default=100000, help="chunk size guard by token limit; 0 disables")
    parser.add_argument(
        "--avg-chars-per-token",
        type=float,
        default=2.0,
        help="estimated chars per token (default: 2.0, better for Chinese+code mixed text)",
    )
    parser.add_argument("--reserved-tokens", type=int, default=1200, help="reserved tokens for system/prompt/output")
    parser.add_argument("--max-requests", type=int, default=0, help="max request count, 0 = unlimited")
    parser.add_argument("--timeout", type=int, default=180, help="HTTP timeout seconds")
    parser.add_argument("--temperature", type=float, default=0.0, help="sampling temperature")
    parser.add_argument("--max-retries", type=int, default=2, help="max retries on invalid JSON")
    parser.add_argument("--show-llm-output", action="store_true", help="print preview of each raw LLM response")
    parser.add_argument("--llm-output-dir", default="", help="directory to save raw LLM outputs")
    parser.add_argument("--llm-output-max-chars", type=int, default=1200, help="preview chars for console print")
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()

    if not input_path.exists():
        print(f"[-] input path does not exist: {input_path}", file=sys.stderr)
        return 2

    if not args.api_key:
        print("[-] Missing API Key. Set Private_API_KEY or use --api-key", file=sys.stderr)
        return 2

    if not args.base_url:
        print("[-] Missing AG_BASE_URL. Set AG_BASE_URL or use --base-url", file=sys.stderr)
        return 2

    if not args.model:
        print("[-] Missing AG_MODEL. Set AG_MODEL or use --model", file=sys.stderr)
        return 2

    files = select_input_files(input_path)
    if not files:
        print(f"[-] no analyzable file found: {input_path}", file=sys.stderr)
        return 2

    if args.token_limit and args.token_limit > 0:
        computed_chars = _conservative_chunk_chars(
            args.token_limit,
            args.reserved_tokens,
            args.avg_chars_per_token,
        )
        print(
            f"[+] token guard enabled: token_limit={args.token_limit}, "
            f"reserved={args.reserved_tokens}, avg_chars_per_token={args.avg_chars_per_token} "
            f"-> conservative_max_chars={computed_chars}"
        )
        args.max_chars = max(64, computed_chars)

    print(f"[+] analyzing {len(files)} files")
    print(f"[+] base_url={args.base_url}")
    print(f"[+] model={args.model}")
    for f in files[:10]:
        print(f"    - {f}")
    if len(files) > 10:
        print(f"    ... and {len(files) - 10} more")

    try:
        result = run_extraction(
            files=files,
            base_url=args.base_url,
            api_key=args.api_key,
            model=args.model,
            prompt=args.prompt,
            timeout=args.timeout,
            temperature=args.temperature,
            max_chars=args.max_chars,
            overlap_chars=args.overlap_chars,
            max_requests=args.max_requests,
            token_limit=args.token_limit,
            avg_chars_per_token=args.avg_chars_per_token,
            reserved_tokens=args.reserved_tokens,
            max_retries=args.max_retries,
            show_llm_output=args.show_llm_output,
            llm_output_dir=args.llm_output_dir,
            llm_output_max_chars=args.llm_output_max_chars,
        )
    except requests.HTTPError as exc:
        body = exc.response.text if exc.response is not None else str(exc)
        print(f"[-] API request failed: {body}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[-] processing failed: {exc}", file=sys.stderr)
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[+] written to: {output_path}")
    print(f"[+] api_endpoints: {len(result['api_endpoints'])}, para: {len(result['para'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
