"""Exact multi-asset renderer contracts for reviewed OpenAI.Codex 26.901 builds.

The profile host moved to app-primary. Keep byte-reviewed replacements in a
manifest; verify every input hash and anchor before writing any renderer file.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

CONTRACT_ID = "windows-26.901"


def contract(*, bundle: str | None = None, extracted: Path | None = None) -> dict:
    if extracted is not None:
        initial = list((extracted / "webview/assets").glob("app-initial-*.js"))
        if len(initial) != 1:
            raise RuntimeError("expected exactly one initial renderer")
        bundle = initial[0].read_text(encoding="utf-8")
    digest = hashlib.sha256(bundle.encode("utf-8")).hexdigest() if bundle is not None else None
    for path in (Path(__file__).with_suffix(".json"), Path(__file__).with_name("renderer_26_901_5280.json")):
        spec = json.loads(path.read_text(encoding="utf-8"))
        if digest is None or spec["initial_sha256"] == digest:
            return spec
    raise RuntimeError("unknown 26.901 renderer binding")


def matches_initial(bundle: str) -> bool:
    try:
        contract(bundle=bundle)
        return True
    except RuntimeError:
        return False


def audit(extracted: Path) -> list[dict]:
    spec = contract(extracted=extracted)
    rows = []
    texts = {}
    for asset, expected in spec["assets"].items():
        path = extracted / asset
        raw = path.read_bytes() if path.is_file() else b""
        texts[asset] = raw.decode("utf-8")
        valid = hashlib.sha256(raw).hexdigest() == expected
        rows.append(dict(name="reviewed asset SHA-256", asset=asset,
                         status="UNCHANGED" if valid else "CHANGED", matched=expected if valid else None,
                         count=int(valid)))
    for op in spec["operations"]:
        count = texts[op["asset"]].count(op["old"])
        rows.append(dict(name=op["name"], asset=op["asset"], count=count,
                         matched=op["name"] if count == 1 else None,
                         status="UNCHANGED" if count == 1 else "MISSING" if count == 0 else "AMBIGUOUS"))
    index = extracted / "webview/index.html"
    count = index.read_text(encoding="utf-8").count("connect-src &#39;self&#39;") if index.is_file() else 0
    rows.append(dict(name="renderer CSP", asset="webview/index.html", count=count,
                     matched="connect-src" if count == 1 else None,
                     status="UNCHANGED" if count == 1 else "MISSING"))
    return rows


def patch(extracted: Path, token: str, project_root: Path, replace_identifiers) -> None:
    rows = audit(extracted)
    if any(row["status"] != "UNCHANGED" for row in rows):
        raise RuntimeError("26.901 exact renderer audit failed before mutation")
    spec = contract(extracted=extracted)
    texts = {name: (extracted / name).read_text(encoding="utf-8") for name in spec["assets"]}
    for op in spec["operations"]:
        texts[op["asset"]] = texts[op["asset"]].replace(op["old"], op["new"], 1)
    component = (project_root / "ui/account-menu.js").read_text(encoding="utf-8")
    component = component.replace("__CODEX_MUX_CONTROL_PORT__", "48123").replace("__CODEX_MUX_CONTROL_TOKEN__", token)
    component = replace_identifiers(component, spec["component_replacements"])
    component += "\nglobalThis.codexMuxRateLimitResets=codexMuxRateLimitResets;\n"
    component += "globalThis.codexMuxConsumeRateLimitReset=codexMuxConsumeRateLimitReset;\n"
    texts[spec["primary"]] += "\n" + component
    # App-server requests can run before app-primary has loaded. This scope
    # adapter has no React or primary-module dependencies and preserves params.
    initial = next(name for name in texts if "/app-initial-" in name)
    texts[initial] += '''
globalThis.codexMuxScopePluginRequest = (method, params) => {
  const id = globalThis.__codexMuxPluginAccountId;
  return id && (params == null || (typeof params === "object" && !Array.isArray(params)))
    ? {...(params || {}), codexMuxAccountId: id} : params;
};
'''
    thread = (project_root / "ui/thread-subscription.js").read_text(encoding="utf-8")
    for old, new in {"__CODEX_MUX_CONTROL_PORT__": "48123", "__CODEX_MUX_CONTROL_TOKEN__": token,
                     "__CODEX_MUX_ROUTE__": spec.get("thread_route", "Ei(ou)"), "__CODEX_MUX_REACT__": "nT",
                     "__CODEX_MUX_JSX__": "rT", "__CODEX_MUX_SECTION__": "Q"}.items():
        thread = thread.replace(old, new)
    texts[spec["thread"]] += "\n" + thread
    index_path = extracted / "webview/index.html"
    index = index_path.read_text(encoding="utf-8").replace(
        "connect-src &#39;self&#39;", "connect-src &#39;self&#39; http://127.0.0.1:48123", 1)
    for name, text in texts.items():
        (extracted / name).write_text(text, encoding="utf-8")
    index_path.write_text(index, encoding="utf-8")
