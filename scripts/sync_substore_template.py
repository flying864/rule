#!/usr/bin/env python3
"""
将 config/clash-party/router-mac-override.yaml 转换并自动同步到
Sub-Store Cloudflare (https://sub.fanco124.eu.org) 的自定义规则模板。
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import yaml


INLINE_CASE_FLAG_RE = re.compile(r"\(\?i\)")


def strip_inline_icase(pattern: str) -> tuple[str, bool]:
    """提取正则中的 (?i)，统一放到最开头以兼容 Sub-Store Cloudflare Worker (V8 RegExp)。"""
    has_icase = bool(INLINE_CASE_FLAG_RE.search(pattern))
    cleaned = INLINE_CASE_FLAG_RE.sub("", pattern)
    return cleaned, has_icase


def build_worker_filter(
    include_filter: str | None,
    exclude_filter: str | None,
) -> str | None:
    """
    Sub-Store Cloudflare 在服务端使用 V8 RegExp 预展开 group.filter，且原生不解析 exclude-filter。
    这里把 Mihomo 的 filter + exclude-filter 合成为单个兼容 V8 的 filter 正则（(?i) 置顶）。
    """
    if not include_filter and not exclude_filter:
        return None

    icase = False
    inc_clean = None
    exc_clean = None

    if include_filter:
        inc_clean, inc_i = strip_inline_icase(str(include_filter))
        icase = icase or inc_i
    if exclude_filter:
        exc_clean, exc_i = strip_inline_icase(str(exclude_filter))
        icase = icase or exc_i

    prefix = "(?i)" if icase else ""

    if inc_clean and exc_clean:
        return f"{prefix}^(?!.*(?:{exc_clean}))(?=.*(?:{inc_clean})).*$"
    if exc_clean:
        return f"{prefix}^(?!.*(?:{exc_clean})).*$"
    return f"{prefix}{inc_clean}"


def convert_proxy_group(
    group: dict[str, Any],
    empty_group_fallbacks: list[str] | None = None,
) -> dict[str, Any]:
    """
    将 Mihomo 本地覆写格式的 proxy-group 转换为 Sub-Store Cloudflare 模板格式：
    1. Worker 不会展开 include-all: true；若保留 include-all 且带 filter，Worker 会删掉 filter
       但保留 include-all，导致客户端把全部节点重新塞回分组。因此必须移除 include-all。
    2. 无 filter/exclude-filter 时，将 include-all: true 转为 proxies 末尾追加 "$all"。
    3. 有 filter/exclude-filter 时，合成为单条 V8 兼容 filter；并确保 proxies 含有兜底项，
       避免无匹配节点的组合订阅（如 oci-4nodes）因 proxies 为空被 Worker 整组删除。
    """
    out = copy.deepcopy(group)
    include_all = bool(out.pop("include-all", False))
    raw_filter = out.pop("filter", None)
    raw_exclude = out.pop("exclude-filter", None)

    proxies: list[str] = [str(p) for p in (out.get("proxies") or [])]

    worker_filter = build_worker_filter(raw_filter, raw_exclude)
    if worker_filter:
        out["filter"] = worker_filter

    if include_all and not worker_filter:
        if "$all" not in proxies:
            proxies.append("$all")

    if worker_filter:
        # 若原配置把 REJECT 放在首位仅为了防空，移到末尾以免压过匹配节点
        if proxies == ["REJECT"]:
            proxies = []
        fallbacks = empty_group_fallbacks if empty_group_fallbacks is not None else []
        for fb in fallbacks:
            if fb not in proxies:
                proxies.append(fb)
        empty_fb = out.get("empty-fallback")
        if empty_fb and str(empty_fb) not in proxies:
            proxies.append(str(empty_fb))
        if not proxies and out.get("type") == "select":
            proxies.append("REJECT")

    out["proxies"] = proxies
    return out


def convert_yaml_to_substore_config(
    raw_yaml: str,
    ruleset_path_from: str = "./ruleset/router-mac/",
    ruleset_path_to: str = "./ruleset/router-universal/",
    filtered_group_fallbacks: list[str] | None = None,
) -> dict[str, Any]:
    data = yaml.safe_load(raw_yaml)
    if not isinstance(data, dict):
        raise ValueError("YAML 顶层必须是映射对象 (dict)")

    rules = data.get("rules") or []
    raw_groups = data.get("proxy-groups") or data.get("proxyGroups") or []
    raw_providers = data.get("rule-providers") or data.get("ruleProviders") or {}

    proxy_groups = [
        convert_proxy_group(
            g,
            empty_group_fallbacks=(
                filtered_group_fallbacks
                if g.get("name") in {"AI", "流媒体"}
                else None
            ),
        )
        for g in raw_groups
    ]

    rule_providers: dict[str, Any] = {}
    for name, provider in raw_providers.items():
        p = copy.deepcopy(provider)
        if isinstance(p, dict) and isinstance(p.get("path"), str):
            p["path"] = p["path"].replace(ruleset_path_from, ruleset_path_to)
        rule_providers[name] = p

    config: dict[str, Any] = {
        "rules": rules,
        "proxyGroups": proxy_groups,
        "ruleProviders": rule_providers,
    }

    # 若未来在覆写中显式声明了以下顶层键，按需透传
    for src_key, dst_key in (
        ("mixed-port", "mixedPort"),
        ("allow-lan", "allowLan"),
        ("log-level", "logLevel"),
        ("mode", "mode"),
        ("dns", "dns"),
        ("sniffer", "sniffer"),
    ):
        if src_key in data:
            config[dst_key] = data[src_key]

    return config


def push_to_substore(
    base_url: str,
    admin_token: str,
    template_id: str,
    template_name: str,
    target: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    encoded_id = urllib.parse.quote(template_id, safe="")
    url = f"{base_url.rstrip('/')}/api/templates/{encoded_id}"

    payload = {
        "id": template_id,
        "name": template_name,
        "target": target,
        "content": json.dumps(config, ensure_ascii=False, indent=2),
    }
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    req = urllib.request.Request(
        url=url,
        data=body,
        method="PATCH",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            ),
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_text = resp.read().decode("utf-8")
            result = json.loads(resp_text)
            if result.get("status") != "success":
                raise RuntimeError(f"Sub-Store 返回非成功状态: {resp_text}")
            return result
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        if exc.code == 404:
            # 若模板尚未创建，自动回退为 POST /api/templates 创建
            post_url = f"{base_url.rstrip('/')}/api/templates"
            post_req = urllib.request.Request(
                url=post_url,
                data=body,
                method="POST",
                headers=dict(req.header_items()),
            )
            with urllib.request.urlopen(post_req, timeout=30) as resp:
                resp_text = resp.read().decode("utf-8")
                result = json.loads(resp_text)
                if result.get("status") != "success":
                    raise RuntimeError(f"POST 创建模板失败: {resp_text}")
                return result
        raise RuntimeError(f"HTTP {exc.code} 调用失败: {err_body}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="同步 Mihomo YAML 覆写至 Sub-Store Cloudflare 模板")
    parser.add_argument(
        "--input",
        default="config/clash-party/router-mac-override.yaml",
        help="源 YAML 覆写文件路径",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("SUB_STORE_URL", "https://sub.fanco124.eu.org"),
        help="Sub-Store Cloudflare 地址",
    )
    parser.add_argument(
        "--template-id",
        default=os.environ.get("SUB_STORE_TEMPLATE_ID", "fanco-router-universal"),
        help="目标模板 ID",
    )
    parser.add_argument(
        "--template-name",
        default=os.environ.get("SUB_STORE_TEMPLATE_NAME", "Fanco 自定义分流（Mihomo）"),
        help="目标模板显示名称",
    )
    parser.add_argument("--target", default="mihomo", choices=["mihomo", "stash"])
    parser.add_argument(
        "--fallback-groups",
        default=os.environ.get("SUB_STORE_FALLBACK_GROUPS", ""),
        help="为 AI/流媒体追加的后备策略组（默认留空：无家宽/AI匹配节点时严格 REJECT 阻断）",
    )
    parser.add_argument("--output-json", help="可选：将转换后的模板 JSON 写入本地文件")
    parser.add_argument("--dry-run", action="store_true", help="仅转换并校验，不发起网络推送")
    args = parser.parse_args()

    yaml_text = Path(args.input).read_text(encoding="utf-8")
    fallbacks = [x.strip() for x in args.fallback_groups.split(",") if x.strip()]
    config = convert_yaml_to_substore_config(
        yaml_text,
        filtered_group_fallbacks=fallbacks,
    )

    rendered = json.dumps(config, ensure_ascii=False, indent=2)
    if args.output_json:
        Path(args.output_json).write_text(rendered + "\n", encoding="utf-8")

    print(
        f"[OK] 转换成功: rules={len(config['rules'])}, "
        f"proxyGroups={len(config['proxyGroups'])}, "
        f"ruleProviders={len(config['ruleProviders'])}"
    )

    if args.dry_run:
        return 0

    token = os.environ.get("SUB_STORE_ADMIN_TOKEN", "").strip()
    if not token:
        if os.environ.get("GITHUB_EVENT_NAME") == "push":
            print(
                "::warning::未检测到 SUB_STORE_ADMIN_TOKEN Secret，已完成 YAML 转换校验但跳过推送。"
                "请在仓库 Settings -> Secrets and variables -> Actions 添加 SUB_STORE_ADMIN_TOKEN。"
            )
            return 0
        print("[ERROR] 缺少环境变量 SUB_STORE_ADMIN_TOKEN", file=sys.stderr)
        return 1

    res = push_to_substore(
        base_url=args.base_url,
        admin_token=token,
        template_id=args.template_id,
        template_name=args.template_name,
        target=args.target,
        config=config,
    )
    saved_id = res.get("data", {}).get("id", args.template_id)
    print(f"[OK] 已同步至 {args.base_url}/my 模板: {saved_id} ({args.template_name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
