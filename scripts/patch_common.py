#!/usr/bin/env python3
"""Platform-independent ASAR and renderer patching helpers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROJECT_VERSION = (PROJECT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
DEFAULT_STATE_ROOT = Path.home() / ".codex-mux"
CONTROL_PORT = 48123


@dataclass(frozen=True)
class AnchorAudit:
    """One semantic renderer hook checked before any renderer mutation."""

    name: str
    asset: str
    status: str
    matched: str | None
    count: int


def load_or_create_token(state_root: Path | None = None) -> str:
    """Reuse the existing mux token so rebuilds keep renderer/mux agreement."""
    root = (state_root or DEFAULT_STATE_ROOT).expanduser()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        pass
    token_path = root / "control-token"
    if token_path.exists():
        token = token_path.read_text(encoding="utf-8").strip()
        if re.fullmatch(r"[0-9a-f]{64}", token) is None:
            raise RuntimeError(f"invalid control token at {token_path}")
        try:
            token_path.chmod(0o600)
        except OSError:
            pass
        return token
    token = secrets.token_hex(32)
    descriptor = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(token)
    return token


def ensure_asar_tool() -> Path:
    """Return the repository-pinned ASAR CLI and reject a mismatched install."""
    asar = PROJECT_ROOT / "node_modules" / ".bin" / "asar"
    if os.name == "nt":
        asar = asar.with_suffix(".cmd")
    package_manifest = PROJECT_ROOT / "node_modules" / "@electron" / "asar" / "package.json"
    expected = json.loads(
        (PROJECT_ROOT / "package.json").read_text(encoding="utf-8")
    )["devDependencies"]["@electron/asar"]
    if not asar.exists() or not package_manifest.is_file():
        raise RuntimeError("run `npm ci --ignore-scripts` before patching")
    actual = json.loads(package_manifest.read_text(encoding="utf-8")).get("version")
    if actual != expected:
        raise RuntimeError(
            f"installed @electron/asar is {actual!r}, expected {expected!r}; "
            "run `npm ci --ignore-scripts`"
        )
    return asar


def replace_javascript_identifiers(source: str, replacements: dict[str, str]) -> str:
    """Retarget injected source to exact minified imports in a known build."""
    for original, replacement in replacements.items():
        pattern = rf"(?<![A-Za-z0-9_$]){re.escape(original)}(?![A-Za-z0-9_$])"
        source, count = re.subn(pattern, replacement, source)
        if count == 0:
            raise RuntimeError(
                f"could not retarget injected JavaScript identifier {original!r}"
            )
    return source


def _variant(
    text: str,
    name: str,
    asset: str,
    current: str,
    renamed: str | None = None,
) -> AnchorAudit:
    current_count = text.count(current)
    if current_count == 1:
        return AnchorAudit(name, asset, "UNCHANGED", "current", current_count)
    if current_count > 1:
        return AnchorAudit(name, asset, "AMBIGUOUS", "current", current_count)
    if renamed is not None:
        renamed_count = text.count(renamed)
        if renamed_count == 1:
            return AnchorAudit(name, asset, "RENAMED", "renamed", renamed_count)
        if renamed_count > 1:
            return AnchorAudit(name, asset, "AMBIGUOUS", "renamed", renamed_count)
    return AnchorAudit(name, asset, "NO LONGER PRESENT", None, 0)


def _asset_with_anchor(
    assets: list[Path],
    name: str,
    glob_label: str,
    anchor: str,
) -> tuple[Path | None, AnchorAudit]:
    matches = [(path, path.read_text(encoding="utf-8").count(anchor)) for path in assets]
    matching = [(path, count) for path, count in matches if count]
    if len(matching) == 1 and matching[0][1] == 1:
        return matching[0][0], AnchorAudit(name, glob_label, "UNCHANGED", str(matching[0][0].name), 1)
    if len(matching) > 1 or any(count > 1 for _, count in matching):
        return None, AnchorAudit(name, glob_label, "AMBIGUOUS", None, sum(count for _, count in matching))
    return None, AnchorAudit(name, glob_label, "NO LONGER PRESENT", None, 0)


def _require_unique(text: str, anchor: str, message: str) -> None:
    count = text.count(anchor)
    if count != 1:
        raise RuntimeError(f"{message} (anchor count: {count})")


def _require_asset(assets: list[Path], anchor: str, message: str) -> Path:
    matching = [path for path in assets if path.read_text(encoding="utf-8").count(anchor) == 1]
    if len(matching) != 1:
        raise RuntimeError(f"{message} (matching assets: {len(matching)})")
    return matching[0]


def _build_6662(bundle: str) -> bool:
    return "function Icl(e){let t=(0,Vcl.c)(248)," in bundle


def _renderer_variant_values(bundle: str) -> dict[str, object]:
    build_6662 = _build_6662(bundle)
    if build_6662:
        return {
            "build_6662": True,
            "component_anchor": "function Icl(e){let t=(0,Vcl.c)(248),",
            "rpc_wrapper": "J9",
            "status_rpc_wrapper": "q9",
            "app_server_anchor": (
                "function Bp(e,t,n){return n==null?N8e.sendRequest(e,t):"
                "N8e.sendRequest(e,t,n)}"
            ),
            "app_server_replacement": (
                "function Bp(e,t,n){let r=codexMuxScopePluginRequest(e,t);"
                "return n==null?N8e.sendRequest(e,r):N8e.sendRequest(e,r,n)}"
            ),
            "profile_query": "let e=await c_.safeGet(`/wham/profiles/me`)",
            "usage_modal": "function E$s(e){",
            "reset_query": (
                "function Ooi(){let e=(0,SI.c)(1),t;return "
                "e[0]===Symbol.for(`react.memo_cache_sentinel`)?"
                "(t={queryKey:[`rate-limit-reset-credits`],queryFn:koi,"
                "refetchInterval:Wp.ONE_MINUTE,staleTime:Wp.FIVE_SECONDS},e[0]=t):"
                "t=e[0],It(t)}"
            ),
            "reset_mutation": (
                "function Aoi(){let e=(0,SI.c)(3),t=ct(),n=Uw(),r;return "
                "e[0]!==n||e[1]!==t?(r={mutationFn:joi,onSuccess:(e,r)=>{"
                "let{creditId:i}=r,a=e.code;if(a===`reset`||a===`already_redeemed`){"
                "let n=e.code===`reset`?e.credit?.id??i:i;"
                "t.setQueryData([`rate-limit-reset-credits`],e=>eoi(e,a,n))}"
                "Promise.all([n([`rate-limit-status`]),n([`rate-limit-reset-credits`])])}},"
                "e[0]=n,e[1]=t,e[2]=r):r=e[2],Qt(r)}"
            ),
            "usage_header": (
                "let _e;t[46]===he?_e=t[47]:"
                "(_e=(0,I0.jsxs)(WL,{children:[he,ge]}),t[46]=he,t[47]=_e);"
            ),
            "usage_header_replacement": (
                "let _e=(0,I0.jsxs)(WL,{children:[he,ge,"
                "window.__codexMuxResetAccountSelector??null]});"
            ),
            "usage_slot": "usageItems:Ct",
            "usage_slot_replacement": "usageItems:(0,$5.jsx)(CodexMuxAccountMenu,{})",
            "open_change": (
                "triggerButton:Dt,onOpenChange:l,children:P",
                "open:s,onOpenChange:l,contentWidth:`panel`,triggerButton:Dt",
            ),
            "open_name": "l",
            "profile_avatar": (
                "avatar:(0,$.jsxs)($.Fragment,{children:["
                "(0,$.jsxs)(`label`,{\"aria-disabled\":z.isPending,"
                "className:Le(`group relative flex size-20 rounded-full outline-none "
                "focus-within:ring-1 focus-within:ring-ring`,"
            ),
            "profile_avatar_replacement": (
                "avatar:(0,$.jsxs)($.Fragment,{children:["
                "globalThis.CodexMuxProfileAvatarStack?.({onSelect:()=>M.refetch()})??null,"
                "(0,$.jsxs)(`label`,{\"aria-disabled\":z.isPending,"
                "className:Le(globalThis.CodexMuxProfileAvatarStack?`hidden`:"
                "`group relative flex size-20 rounded-full outline-none "
                "focus-within:ring-1 focus-within:ring-ring`,"
            ),
            "profile_name": (
                "displayName:Ze??(0,$.jsx)(o,{id:`profile.nameFallback`,"
                "defaultMessage:`ChatGPT user`,description:`Fallback profile display name`})"
            ),
            "profile_name_replacement": (
                "displayName:globalThis.__codexMuxSelectedProfileAccountId?"
                "(Ze??(0,$.jsx)(o,{id:`profile.nameFallback`,"
                "defaultMessage:`ChatGPT user`,"
                "description:`Fallback profile display name`})):null"
            ),
            "profile_identity": (
                "username:Ke==null?null:(0,$.jsx)(o,{id:`profile.usernameValue`,"
                "defaultMessage:`@{username}`,"
                "description:`Profile username shown with an at-sign prefix`,"
                "values:{username:Ke}})"
            ),
            "profile_identity_replacement": (
                "username:globalThis.__codexMuxSelectedProfileAccountId&&Ke!=null?"
                "(0,$.jsx)(o,{id:`profile.usernameValue`,"
                "defaultMessage:`@{username}`,"
                "description:`Profile username shown with an at-sign prefix`,"
                "values:{username:Ke}}):null"
            ),
            "plugin_anchor": "ee=(0,tc.jsxs)(tc.Fragment,{children:[H,U]})",
            "plugin_replacement": (
                "ee=(0,tc.jsxs)(tc.Fragment,{children:[globalThis.CodexMuxPluginScope?.()??null,H,U]})"
            ),
            "plugin_glob": "plugins-page-*.js",
            "thread_anchor": "function bE(){let e=(0,SE.c)(1)",
            "thread_component_replacements": {"$n": "jf", "sr": "Pa", "TE": "jy", "zE": "CE", "K": "q"},
            "summary_component": "CE",
        }
    return {
        "build_6662": False,
        "component_anchor": "function wXc({sidebarFooter:e,triggerButton:t})",
        "rpc_wrapper": "q9",
        "status_rpc_wrapper": "K9",
        "app_server_anchor": (
            "function gm(e,t,n){return n==null?h6e.sendRequest(e,t):"
            "h6e.sendRequest(e,t,n)}"
        ),
        "app_server_replacement": (
            "function gm(e,t,n){let r=codexMuxScopePluginRequest(e,t);"
            "return n==null?h6e.sendRequest(e,r):h6e.sendRequest(e,r,n)}"
        ),
        "profile_query": "let e=await T_.safeGet(`/wham/profiles/me`)",
        "usage_modal": "function QLs(e){",
        "reset_query": (
            "function l6r(){let e=(0,$F.c)(1),t;return "
            "e[0]===Symbol.for(`react.memo_cache_sentinel`)?"
            "(t={queryKey:[`rate-limit-reset-credits`],queryFn:u6r,"
            "refetchInterval:vm.ONE_MINUTE,staleTime:vm.FIVE_SECONDS},e[0]=t):"
            "t=e[0],Lt(t)}"
        ),
        "reset_mutation": (
            "function d6r(){let e=(0,$F.c)(3),t=lt(),n=zO(),r;return "
            "e[0]!==n||e[1]!==t?(r={mutationFn:f6r,onSuccess:(e,r)=>{"
            "let{creditId:i}=r,a=e.code;if(a===`reset`||a===`already_redeemed`){"
            "let n=e.code===`reset`?e.credit?.id??i:i;"
            "t.setQueryData([`rate-limit-reset-credits`],e=>F3r(e,a,n))}"
            "Promise.all([n([`rate-limit-status`]),n([`rate-limit-reset-credits`])])}},"
            "e[0]=n,e[1]=t,e[2]=r):r=e[2],$t(r)}"
        ),
        "usage_header": (
            "let ve;t[46]===ge?ve=t[47]:"
            "(ve=(0,k2.jsxs)(LL,{children:[ge,_e]}),t[46]=ge,t[47]=ve);"
        ),
        "usage_header_replacement": (
            "let ve=(0,k2.jsxs)(LL,{children:[ge,_e,"
            "window.__codexMuxResetAccountSelector??null]});"
        ),
        "usage_slot": "usageItems:Ge",
        "usage_slot_replacement": "usageItems:(0,e7.jsx)(CodexMuxAccountMenu,{})",
        "open_change": (
            "triggerButton:Ke,onOpenChange:o,children:(0,e7.jsx)(bXc",
            "return(0,e7.jsx)(vH,{open:a,onOpenChange:o,contentWidth:`panel`",
        ),
        "open_name": "o",
        "profile_avatar": (
            "children:[(0,$.jsxs)(`div`,{className:`relative mb-4 size-20`,children:["
        ),
        "profile_avatar_replacement": (
            "children:[globalThis.CodexMuxProfileAvatarStack?.({onSelect:()=>A.refetch()})??null,"
            "(0,$.jsxs)(`div`,{className:globalThis.CodexMuxProfileAvatarStack?"
            "`hidden`:`relative mb-4 size-20`,children:["
        ),
        "profile_name": "className:`flex w-full justify-center`",
        "profile_name_replacement": (
            "className:globalThis.__codexMuxSelectedProfileAccountId&&!A.isFetching?"
            "`flex w-full justify-center`:`hidden`"
        ),
        "profile_identity": (
            "className:`mt-1 flex min-h-7 items-center gap-1.5 text-base leading-5 "
            "font-normal text-token-text-tertiary`"
        ),
        "profile_identity_replacement": (
            "className:globalThis.__codexMuxSelectedProfileAccountId&&!A.isFetching?"
            "`mt-1 flex min-h-7 items-center gap-1.5 text-base leading-5 font-normal "
            "text-token-text-tertiary`:`hidden`"
        ),
        "plugin_anchor": "action:F,children:w})",
        "plugin_replacement": "action:F,children:[globalThis.CodexMuxPluginScope?.()??null,w]})",
        "plugin_glob": "plugins-settings-*.js",
        "thread_anchor": "function bE(){let e=(0,wE.c)(57)",
        "thread_component_replacements": {},
        "summary_component": "zE",
    }


def audit_renderer_anchors(extracted: Path) -> list[AnchorAudit]:
    """Audit exact semantic hooks without changing the extracted ASAR."""
    webview = extracted / "webview"
    assets = webview / "assets"
    index_path = webview / "index.html"
    if not index_path.is_file():
        return [AnchorAudit("renderer CSP", "webview/index.html", "NO LONGER PRESENT", None, 0)]
    index = index_path.read_text(encoding="utf-8")
    initial_bundles = list(assets.glob("app-initial-*.js"))
    if len(initial_bundles) != 1:
        return [AnchorAudit("initial renderer bundle", "webview/assets", "AMBIGUOUS", None, len(initial_bundles))]
    bundle_path = initial_bundles[0]
    bundle = bundle_path.read_text(encoding="utf-8")
    values = _renderer_variant_values(bundle)
    old_values = _renderer_variant_values(bundle.replace("function Icl(e){let t=(0,Vcl.c)(248),", "function wXc({sidebarFooter:e,triggerButton:t})"))
    build_6662 = bool(values["build_6662"])
    audit: list[AnchorAudit] = [
        AnchorAudit(
            "renderer CSP",
            "webview/index.html",
            "UNCHANGED" if index.count("connect-src &#39;self&#39;") == 1 else "NO LONGER PRESENT",
            "connect-src &#39;self&#39;" if index.count("connect-src &#39;self&#39;") == 1 else None,
            index.count("connect-src &#39;self&#39;"),
        )
    ]
    def add_variant(name: str, current: str, renamed: str | None = None) -> None:
        audit.append(_variant(bundle, name, bundle_path.name, current, renamed))

    def add_key_variant(name: str, key: str) -> None:
        current = str(old_values[key] if build_6662 else values[key])
        renamed = str(values[key]) if build_6662 else None
        add_variant(name, current, renamed)

    add_key_variant("native profile menu", "component_anchor")
    add_key_variant("app-server request bridge", "app_server_anchor")
    add_key_variant("profile statistics request", "profile_query")
    add_key_variant("native usage modal", "usage_modal")
    add_key_variant("reset-credit query", "reset_query")
    add_key_variant("reset-credit mutation", "reset_mutation")
    add_variant(
        "usage-window selection",
        "let y=v;if(g!=null){",
    )
    add_key_variant("usage sheet header", "usage_header")
    add_key_variant("usage menu slot", "usage_slot")

    mapping_names = (
        "list-apps RPC mapping",
        "list-installed-apps RPC mapping",
        "read-apps RPC mapping",
        "login-mcp-server RPC mapping",
        "list-mcp-server-status RPC mapping",
        "listMcpServers RPC wrapper",
        "mcpServerStatus/list RPC call",
    )
    current_mappings = _plugin_mapping_anchors(
        str(values["rpc_wrapper"]),
        str(values["status_rpc_wrapper"]),
    )
    old_mappings = _plugin_mapping_anchors(
        str(old_values["rpc_wrapper"]),
        str(old_values["status_rpc_wrapper"]),
    )
    for name, current_mapping, old_mapping in zip(
        mapping_names,
        current_mappings,
        old_mappings,
    ):
        audit.append(
            _variant(
                bundle,
                name,
                bundle_path.name,
                old_mapping if build_6662 else current_mapping,
                current_mapping if build_6662 else None,
            )
        )

    for index, anchor in enumerate(values["open_change"]):
        old_anchor = old_values["open_change"][index]
        audit.append(
            _variant(
                bundle,
                f"profile menu open-state hook {index + 1}",
                bundle_path.name,
                old_anchor if build_6662 else anchor,
                anchor if build_6662 else None,
            )
        )
    for message in (
        "defaultMessage:`You’re out of Codex and Work usage`",
        "defaultMessage:`You’ve used all Codex and Work usage`",
        "defaultMessage:`You’ve reached your usage limit`",
    ):
        audit.append(_variant(bundle, "subscription depletion alert", bundle_path.name, message))

    profile_assets = list(assets.glob("profile-*.js"))
    profile_path = profile_assets[0] if len(profile_assets) == 1 else None
    profile_text = profile_path.read_text(encoding="utf-8") if profile_path else ""
    for name, key in (
        ("Profile avatar", "profile_avatar"),
        ("Profile display name", "profile_name"),
        ("Profile username and plan", "profile_identity"),
    ):
        current = str(old_values[key] if build_6662 else values[key])
        renamed = str(values[key]) if build_6662 else None
        audit.append(_variant(profile_text, name, profile_path.name if profile_path else "profile-*.js", current, renamed))

    plugin_assets = list(assets.glob(str(values["plugin_glob"])))
    plugin_path: Path | None = None
    if build_6662:
        old_plugin_assets = list(assets.glob(str(old_values["plugin_glob"])))
        _, old_plugin_audit = _asset_with_anchor(
            old_plugin_assets,
            "Plugins settings content",
            str(old_values["plugin_glob"]),
            str(old_values["plugin_anchor"]),
        )
        plugin_path, new_plugin_audit = _asset_with_anchor(
            plugin_assets,
            "Plugins settings content",
            str(values["plugin_glob"]),
            str(values["plugin_anchor"]),
        )
        if new_plugin_audit.status == "UNCHANGED" and old_plugin_audit.status == "NO LONGER PRESENT":
            plugin_audit = AnchorAudit(
                "Plugins settings content",
                str(values["plugin_glob"]),
                "MOVED",
                new_plugin_audit.matched,
                new_plugin_audit.count,
            )
        elif new_plugin_audit.status == "UNCHANGED":
            plugin_audit = AnchorAudit(
                "Plugins settings content",
                str(values["plugin_glob"]),
                "RENAMED",
                new_plugin_audit.matched,
                new_plugin_audit.count,
            )
        else:
            plugin_audit = new_plugin_audit
    else:
        plugin_path, plugin_audit = _asset_with_anchor(
            plugin_assets,
            "Plugins settings content",
            str(values["plugin_glob"]),
            str(values["plugin_anchor"]),
        )
    audit.append(plugin_audit)

    thread_assets = list(assets.glob("local-conversation-thread-*.js"))
    if build_6662:
        _, old_thread_audit = _asset_with_anchor(
            thread_assets,
            "thread summary source component",
            "local-conversation-thread-*.js",
            str(old_values["thread_anchor"]),
        )
        thread_path, new_thread_audit = _asset_with_anchor(
            thread_assets,
            "thread summary source component",
            "local-conversation-thread-*.js",
            str(values["thread_anchor"]),
        )
        if new_thread_audit.status == "UNCHANGED" and old_thread_audit.status == "NO LONGER PRESENT":
            thread_audit = AnchorAudit(
                "thread summary source component",
                "local-conversation-thread-*.js",
                "RENAMED",
                new_thread_audit.matched,
                new_thread_audit.count,
            )
        else:
            thread_audit = new_thread_audit
    else:
        thread_path, thread_audit = _asset_with_anchor(
            thread_assets,
            "thread summary source component",
            "local-conversation-thread-*.js",
            str(values["thread_anchor"]),
        )
    audit.append(thread_audit)
    thread_text = thread_path.read_text(encoding="utf-8") if thread_path else ""
    audit.append(_variant(thread_text, "thread summary section list", "local-conversation-thread-*.js", "children:[c,l,u,d,f,p,m,h,g,_,v,y,b,x]"))
    return audit


def _plugin_mapping_anchors(rpc_wrapper: str, status_rpc_wrapper: str) -> tuple[str, ...]:
    return (
        f'"list-apps":{rpc_wrapper}((e,{{priority:t,source:n,timeoutMs:r,'
        "trace:i,...a})=>e.sendRequest(`app/list`,a,",
        f'"list-installed-apps":{rpc_wrapper}((e,t)=>'
        "e.sendRequest(`app/installed`,t))",
        f'"read-apps":{rpc_wrapper}((e,t)=>e.sendRequest(`app/read`,t))',
        f'"login-mcp-server":{rpc_wrapper}((e,t)=>'
        "e.sendRequest(`mcpServer/oauth/login`,t))",
        f'"list-mcp-server-status":{status_rpc_wrapper}((e,{{priority:t,'
        "source:n,timeoutMs:r,trace:i,...a})=>e.listMcpServers(a,",
        "listMcpServers(e,t){let n=JSON.stringify({options:t,params:e})",
        "let i=this.sendRequest(`mcpServerStatus/list`,e,t);",
    )


def patch_renderer(extracted: Path, token: str) -> list[AnchorAudit]:
    """Patch renderer account/routing surfaces after exact semantic validation."""
    audit = audit_renderer_anchors(extracted)
    failed_audit = [
        item for item in audit if item.status in {"NO LONGER PRESENT", "AMBIGUOUS"}
    ]
    if failed_audit:
        details = "; ".join(
            f"{item.name}: {item.status} ({item.asset})" for item in failed_audit
        )
        raise RuntimeError(f"renderer anchor audit failed: {details}")
    webview = extracted / "webview"
    index_path = webview / "index.html"
    index = index_path.read_text(encoding="utf-8")
    connect_anchor = "connect-src &#39;self&#39;"
    _require_unique(index, connect_anchor, "could not find ChatGPT renderer CSP connect-src")
    index_path.write_text(index.replace(connect_anchor, f"{connect_anchor} http://127.0.0.1:{CONTROL_PORT}", 1), encoding="utf-8")

    initial_bundles = list((webview / "assets").glob("app-initial-*.js"))
    if len(initial_bundles) != 1:
        raise RuntimeError(f"expected one ChatGPT initial renderer bundle, found {len(initial_bundles)}")
    bundle_path = initial_bundles[0]
    bundle = bundle_path.read_text(encoding="utf-8")
    if "function CodexMuxAccountMenu(" in bundle:
        raise RuntimeError("source app already contains the Codex multiplexer menu")
    values = _renderer_variant_values(bundle)
    build_6662 = bool(values["build_6662"])
    component = (PROJECT_ROOT / "ui" / "account-menu.js").read_text(encoding="utf-8")
    component = component.replace("__CODEX_MUX_CONTROL_PORT__", str(CONTROL_PORT))
    component = component.replace("__CODEX_MUX_CONTROL_TOKEN__", token)
    replacements = values["component_replacements"] if "component_replacements" in values else (
        {"e7": "$5", "kXc": "Hcl", "Lo": "Fo", "BW": "RU", "QLs": "E$s", "_H": "GV", "S2": "E0", "CH": "ZV", "jLa": "x$a", "lt": "ct"}
        if build_6662
        else {}
    )
    if replacements:
        component = replace_javascript_identifiers(component, replacements)
    component_anchor = str(values["component_anchor"])
    _require_unique(bundle, component_anchor, "could not find the native ChatGPT profile menu component")
    bundle = bundle.replace(component_anchor, component + "\n" + component_anchor, 1)

    for mapping_anchor in _plugin_mapping_anchors(str(values["rpc_wrapper"]), str(values["status_rpc_wrapper"])):
        _require_unique(bundle, mapping_anchor, "could not verify the native Plugins request-to-RPC mapping")
    app_server_anchor = str(values["app_server_anchor"])
    _require_unique(bundle, app_server_anchor, "could not find the native app-server request bridge")
    bundle = bundle.replace(app_server_anchor, str(values["app_server_replacement"]), 1)

    profile_query_anchor = str(values["profile_query"])
    _require_unique(bundle, profile_query_anchor, "could not find the native profile stats request")
    bundle = bundle.replace(profile_query_anchor, "let e=await codexMuxProfileData(globalThis.__codexMuxSelectedProfileAccountId??null)", 1)

    usage_modal_anchor = str(values["usage_modal"])
    _require_unique(bundle, usage_modal_anchor, "could not find the native Usage modal component")
    bundle = bundle.replace(usage_modal_anchor, usage_modal_anchor + "CodexMuxUseResetAccountState();", 1)

    reset_query_anchor = str(values["reset_query"])
    _require_unique(bundle, reset_query_anchor, "could not find the native reset-credit query")
    reset_query_replacement = (
        "function Ooi(){let e=window.__codexMuxResetAccountId;return It({queryKey:[`rate-limit-reset-credits`,e??`primary`],queryFn:e?()=>codexMuxRateLimitResets(e):koi,refetchInterval:Wp.ONE_MINUTE,staleTime:Wp.FIVE_SECONDS})}"
        if build_6662
        else "function l6r(){let e=window.__codexMuxResetAccountId;return Lt({queryKey:[`rate-limit-reset-credits`,e??`primary`],queryFn:e?()=>codexMuxRateLimitResets(e):u6r,refetchInterval:vm.ONE_MINUTE,staleTime:vm.FIVE_SECONDS})}"
    )
    bundle = bundle.replace(reset_query_anchor, reset_query_replacement, 1)

    reset_mutation_anchor = str(values["reset_mutation"])
    _require_unique(bundle, reset_mutation_anchor, "could not find the native reset-credit mutation")
    reset_mutation_replacement = (
        "function Aoi(){let e=ct(),t=Uw(),n=window.__codexMuxResetAccountId,r=[`rate-limit-reset-credits`,n??`primary`];return Qt({mutationFn:n?i=>codexMuxConsumeRateLimitReset(n,i):joi,onSuccess:(n,i)=>{let{creditId:a}=i,o=n.code;if(o===`reset`||o===`already_redeemed`){let t=o===`reset`?n.credit?.id??a:a;e.setQueryData(r,e=>eoi(e,o,t))}Promise.all([t([`rate-limit-status`]),t(r)])}})}"
        if build_6662
        else "function d6r(){let e=lt(),t=zO(),n=window.__codexMuxResetAccountId,r=[`rate-limit-reset-credits`,n??`primary`];return $t({mutationFn:n?i=>codexMuxConsumeRateLimitReset(n,i):f6r,onSuccess:(n,i)=>{let{creditId:a}=i,o=n.code;if(o===`reset`||o===`already_redeemed`){let t=o===`reset`?n.credit?.id??a:a;e.setQueryData(r,e=>F3r(e,o,t))}Promise.all([t([`rate-limit-status`]),t(r)])}})}"
    )
    bundle = bundle.replace(reset_mutation_anchor, reset_mutation_replacement, 1)

    selected_usage_anchor = "let y=v;if(g!=null){"
    _require_unique(bundle, selected_usage_anchor, "could not find the native usage-window selection")
    bundle = bundle.replace(selected_usage_anchor, "let y=window.__codexMuxSelectedUsageWindows??v;if(g!=null){", 1)
    usage_header_anchor = str(values["usage_header"])
    _require_unique(bundle, usage_header_anchor, "could not find the native Usage sheet header")
    bundle = bundle.replace(usage_header_anchor, str(values["usage_header_replacement"]), 1)
    usage_anchor = str(values["usage_slot"])
    _require_unique(bundle, usage_anchor, "could not find the native ChatGPT usage menu slot")
    bundle = bundle.replace(usage_anchor, str(values["usage_slot_replacement"]), 1)

    for anchor in values["open_change"]:
        _require_unique(bundle, anchor, "could not find a native profile menu open-state hook")
        open_name = str(values["open_name"])
        bundle = bundle.replace(anchor, anchor.replace(f"onOpenChange:{open_name}", f"onOpenChange:CodexMuxProfileMenuOpenChange({open_name})"), 1)
    for depleted_anchor in (
        "defaultMessage:`You’re out of Codex and Work usage`",
        "defaultMessage:`You’ve used all Codex and Work usage`",
        "defaultMessage:`You’ve reached your usage limit`",
    ):
        _require_unique(bundle, depleted_anchor, "could not find a native subscription depletion alert")
        bundle = bundle.replace(depleted_anchor, "defaultMessage:`All connected subscriptions are depleted`", 1)
    bundle_path.write_text(bundle, encoding="utf-8")

    profile_assets = list((webview / "assets").glob("profile-*.js"))
    if len(profile_assets) != 1:
        raise RuntimeError(f"expected one native Profile settings bundle, found {len(profile_assets)}")
    profile_path = profile_assets[0]
    profile = profile_path.read_text(encoding="utf-8")
    for key, message in (
        ("profile_avatar", "could not find the native Profile avatar"),
        ("profile_name", "could not find the native Profile display name"),
        ("profile_identity", "could not find the native Profile username and plan badge"),
    ):
        _require_unique(profile, str(values[key]), message)
    profile = profile.replace(str(values["profile_avatar"]), str(values["profile_avatar_replacement"]), 1)
    profile = profile.replace(str(values["profile_name"]), str(values["profile_name_replacement"]), 1)
    profile = profile.replace(str(values["profile_identity"]), str(values["profile_identity_replacement"]), 1)
    profile_path.write_text(profile, encoding="utf-8")

    plugin_assets = list((webview / "assets").glob(str(values["plugin_glob"])))
    plugin_path = _require_asset(plugin_assets, str(values["plugin_anchor"]), "could not find the native Plugins settings bundle")
    plugin = plugin_path.read_text(encoding="utf-8")
    _require_unique(plugin, str(values["plugin_anchor"]), "could not find the native Plugins settings content")
    plugin_path.write_text(plugin.replace(str(values["plugin_anchor"]), str(values["plugin_replacement"]), 1), encoding="utf-8")

    thread_assets = list((webview / "assets").glob("local-conversation-thread-*.js"))
    thread_path = _require_asset(thread_assets, str(values["thread_anchor"]), "could not find the native local conversation renderer bundle")
    thread = thread_path.read_text(encoding="utf-8")
    thread_component = (PROJECT_ROOT / "ui" / "thread-subscription.js").read_text(encoding="utf-8")
    thread_component = thread_component.replace("__CODEX_MUX_CONTROL_PORT__", str(CONTROL_PORT)).replace("__CODEX_MUX_CONTROL_TOKEN__", token)
    if values["thread_component_replacements"]:
        thread_component = replace_javascript_identifiers(thread_component, values["thread_component_replacements"])
    _require_unique(thread, str(values["thread_anchor"]), "could not find the native thread summary sources component")
    thread = thread.replace(str(values["thread_anchor"]), thread_component + "\n" + str(values["thread_anchor"]), 1)
    summary_anchor = "children:[c,l,u,d,f,p,m,h,g,_,v,y,b,x]"
    _require_unique(thread, summary_anchor, "could not find the native thread summary section list")
    thread = thread.replace(summary_anchor, "children:[c,l,u,d,f,(0," + str(values["summary_component"]) + ".jsx)(CodexMuxThreadSubscription,{}),p,m,h,g,_,v,y,b,x]", 1)
    thread_path.write_text(thread, encoding="utf-8")
    return audit


def sha256(path: Path) -> str:
    """Hash a generated artifact without reading any credential-bearing files."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
