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


@dataclass(frozen=True)
class RendererVariant:
    """A renderer patch contract selected by several exact build fingerprints."""

    variant_id: str
    package_name: str | None
    package_version: str | None
    app_asar_sha256: str | None
    fingerprints: tuple[str, ...]
    values: dict[str, object]


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
    semantic: str | None = None,
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
    if semantic is not None:
        semantic_count = text.count(semantic)
        if semantic_count == 1:
            return AnchorAudit(name, asset, "SEMANTICALLY_CHANGED", "semantic", semantic_count)
        if semantic_count > 1:
            return AnchorAudit(name, asset, "AMBIGUOUS", "semantic", semantic_count)
    return AnchorAudit(name, asset, "MISSING", None, 0)


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
    return None, AnchorAudit(name, glob_label, "MISSING", None, 0)


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


def _legacy_renderer_variant_values(bundle: str) -> dict[str, object]:
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
            "usage_slot_replacement": (
                "usageItems:(globalThis.__codexMuxAccountMenuInjected=true,"
                "(0,$5.jsx)(CodexMuxAccountMenu,{}))"
            ),
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
        "usage_slot_replacement": (
            "usageItems:(globalThis.__codexMuxAccountMenuInjected=true,"
            "(0,e7.jsx)(CodexMuxAccountMenu,{}))"
        ),
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


WINDOWS_26_820_PACKAGE_NAME = "OpenAI.Codex"
WINDOWS_26_820_PACKAGE_VERSION = "26.820.7780.0"
WINDOWS_26_820_ASAR_SHA256 = "5df8bf5a9d30742919390ab11fa419e83aab0891152569a42c6ea4abf15386c2"


def _windows_26_820_renderer_values() -> dict[str, object]:
    """Return the exact renderer contract for the acquired Windows build."""
    component_anchor = (
        "function Jyl(e){let t=(0,Yyl.c)(33),{accountIcon:n,accountLabel:r,"
        "additionalItems:i,displayName:a,identityItems:o,isPetVisible:s,"
        "onCopyUserId:c,onLogOut:l,onOpenProfile:u,onOpenSettings:d,"
        "onOpenWorkspaceSettings:f,onTogglePet:p,settingsShortcut:m,"
        "usageItems:h,workspaceSettingsRightIcon:g}=e"
    )
    app_server_anchor = (
        "function qg(e,t){let n=e.get(Jg);if(n==null)throw Error("
        "`AppServerManager RPC is not connected`);return n.forHost(t)}"
    )
    usage_header = (
        "children:(0,d1.jsx)(Z,{id:`codex.rateLimitResetPromptModal.usageTrackingHeading`,"
        "defaultMessage:`Usage`,description:`Heading for the Codex usage limit modal`})"
    )
    reset_query = (
        "function WAa(){let e=(0,uH.c)(1),t;return e[0]===Symbol.for(`react.memo_cache_sentinel`)?"
        "(t={queryKey:[`rate-limit-reset-credits`],queryFn:GAa,"
        "refetchInterval:nm.ONE_MINUTE,staleTime:nm.FIVE_SECONDS},e[0]=t):"
        "t=e[0],Lt(t)}"
    )
    reset_mutation = (
        "function KAa(){let e=(0,uH.c)(3),t=lt(),n=AS(),r;return "
        "e[0]!==n||e[1]!==t?(r={mutationFn:qAa,onSuccess:(e,r)=>{"
        "let{creditId:i}=r,a=e.code;if(a===`reset`||a===`already_redeemed`){"
        "let n=e.code===`reset`?e.credit?.id??i:i;"
        "t.setQueryData([`rate-limit-reset-credits`],e=>gAa(e,a,n))}"
        "Promise.all([n([`rate-limit-status`]),n([`rate-limit-reset-credits`])])}},"
        "e[0]=n,e[1]=t,e[2]=r):r=e[2],$t(r)}"
    )
    plugin_mappings = (
        {
            "name": "list-installed-apps RPC mapping",
            "current": "qg(e,n).sendRequest(`app/installed`,t?{forceRefresh:!0}:{})",
            "replacement": (
                "qg(e,n).sendRequest(`app/installed`,"
                'codexMuxScopePluginRequest("list-installed-apps",t?{forceRefresh:!0}:{}))'
            ),
        },
        {
            "name": "read-apps RPC mapping",
            "current": "qg(e,n).sendRequest(`app/read`,{appIds:t})",
            "replacement": (
                "qg(e,n).sendRequest(`app/read`,"
                'codexMuxScopePluginRequest("read-apps",{appIds:t}))'
            ),
        },
        {
            "name": "list-apps RPC mapping",
            "current": (
                "qg(e,n).sendRequest(`app/list`,{cursor:i,limit:E9r,"
                "forceRefetch:t},{trace:a})"
            ),
            "replacement": (
                "qg(e,n).sendRequest(`app/list`,"
                'codexMuxScopePluginRequest("list-apps",{cursor:i,limit:E9r,forceRefetch:t}),'
                "{trace:a})"
            ),
        },
        {
            "name": "login-mcp-server RPC mapping",
            "current": "t.sendRequest(`mcpServer/oauth/login`,e)",
            "replacement": (
                't.sendRequest(`mcpServer/oauth/login`,'
                'codexMuxScopePluginRequest("login-mcp-server",e))'
            ),
        },
        {
            "name": "list-mcp-server-status RPC mapping",
            "current": (
                "qg(e,t).listMcpServers({cursor:i,detail:n,limit:100},"
                "r===void 0?void 0:{trace:r})"
            ),
            "replacement": (
                "qg(e,t).listMcpServers("
                'codexMuxScopePluginRequest("list-mcp-server-status",{cursor:i,detail:n,limit:100}),'
                "r===void 0?void 0:{trace:r})"
            ),
        },
        {
            "name": "listMcpServers RPC wrapper",
            "current": (
                "listMcpServers(e,t){let n=JSON.stringify({options:t,params:e}),"
                "r=this.mcpServerStatusPromises.get(n);if(r)return r;"
                "let i=this.sendRequest(`mcpServerStatus/list`,e,t);"
            ),
            "replacement": (
                "listMcpServers(e,t){let n=JSON.stringify({options:t,params:e}),"
                "r=this.mcpServerStatusPromises.get(n);if(r)return r;"
                "let i=this.sendRequest(`mcpServerStatus/list`,e,t);"
            ),
        },
        {
            "name": "mcpServerStatus/list RPC call",
            "current": "this.sendRequest(`mcpServerStatus/list`,e,t)",
            "replacement": "this.sendRequest(`mcpServerStatus/list`,e,t)",
        },
    )
    return {
        "variant_id": "windows-26.820",
        "build_6662": False,
        "component_anchor": component_anchor,
        "component_replacements": {
            "e7": "p8",
            "kXc": "ibl",
            "Lo": "ds",
            "BW": "Tz",
            "QLs": "g6s",
            "_H": "UI",
            "S2": "DP",
            "CH": "YI",
            "jLa": "aza",
        },
        "rpc_wrapper": "",
        "status_rpc_wrapper": "",
        "app_server_anchor": app_server_anchor,
        "app_server_replacement": app_server_anchor,
        "profile_query": "let e=await Ob.safeGet(`/wham/profiles/me`)",
        "usage_modal": "function c6s(e){",
        "reset_query": reset_query,
        "reset_mutation": reset_mutation,
        "usage_header": usage_header,
        "usage_header_replacement": (
            "children:(0,d1.jsxs)(d1.Fragment,{children:["
            + usage_header[len("children:") :]
            + ",globalThis.__codexMuxResetAccountSelector??null]})"
        ),
        "usage_slot": "usageItems:wt",
        "usage_slot_replacement": (
            "usageItems:(globalThis.__codexMuxAccountMenuInjected=true,"
            "(0,p8.jsx)(CodexMuxAccountMenu,{}))"
        ),
        "open_change": (
            "open:s,side:`top`,sideOffset:6,triggerButton:Ot,onOpenChange:l,children:N",
        ),
        "open_name": "l",
        "open_preserved": "open:s,onOpenChange:l,contentWidth:`panel`,triggerButton:Ot",
        "profile_avatar": (
            "avatar:(0,$.jsxs)($.Fragment,{children:[(0,$.jsxs)(`label`,"
            '{"aria-disabled":I.isPending,className:$t(`group relative flex size-20 '
            "rounded-full outline-none focus-within:ring-1 focus-within:ring-ring`,"
        ),
        "profile_avatar_replacement": (
            "avatar:(0,$.jsxs)($.Fragment,{children:["
            "globalThis.CodexMuxProfileAvatarStack?.({onSelect:()=>j.refetch()})??null,"
            "(0,$.jsxs)(`label`,{\"aria-disabled\":I.isPending,"
            "className:$t(globalThis.CodexMuxProfileAvatarStack?`hidden`:"
            "`group relative flex size-20 rounded-full outline-none "
            "focus-within:ring-1 focus-within:ring-ring`,"
        ),
        "profile_name": (
            "displayName:Ye??(0,$.jsx)(J,{id:`profile.nameFallback`,"
            "defaultMessage:`ChatGPT user`,description:`Fallback profile display name`})"
        ),
        "profile_name_replacement": (
            "displayName:globalThis.__codexMuxSelectedProfileAccountId?"
            "Ye??(0,$.jsx)(J,{id:`profile.nameFallback`,"
            "defaultMessage:`ChatGPT user`,description:`Fallback profile display name`}):null"
        ),
        "profile_identity": (
            "username:qe==null?null:(0,$.jsx)(J,{id:`profile.usernameValue`,"
            "defaultMessage:`@{username}`,description:`Profile username shown with an at-sign prefix`,"
            "values:{username:qe}})"
        ),
        "profile_identity_replacement": (
            "username:globalThis.__codexMuxSelectedProfileAccountId&&qe!=null?"
            "(0,$.jsx)(J,{id:`profile.usernameValue`,"
            "defaultMessage:`@{username}`,description:`Profile username shown with an at-sign prefix`,"
            "values:{username:qe}}):null"
        ),
        "plugin_anchor": "contentAfterConnected:(0,$.jsxs)($.Fragment,{children:[",
        "plugin_replacement": (
            "contentAfterConnected:(0,$.jsxs)($.Fragment,{children:["
            "globalThis.CodexMuxPluginScope?.()??null,"
        ),
        "plugin_glob": "plugins-page-*.js",
        "thread_anchor": "function $T(){let e=(0,rE.c)(58),",
        "thread_summary_anchor": (
            "(0,aE.jsx)(W.Section,{sectionKey:`tool-sources`,after:z,title:B,"
            "titleSuffix:V,children:H})"
        ),
        "thread_component_replacements": {},
        "thread_route": "null",
        "thread_react": "iE",
        "thread_jsx": "aE",
        "thread_section": "W",
        "summary_component": "aE",
        "plugin_mappings": plugin_mappings,
    }


WINDOWS_26_825_PACKAGE_NAME = "OpenAI.Codex"
WINDOWS_26_825_PACKAGE_VERSION = "26.825.5331.0"
WINDOWS_26_825_ASAR_SHA256 = "178b65229452b17b0203ab41d5ceafedccd770c9bd42d239a6d048d27d80252b"


def _windows_26_825_renderer_values() -> dict[str, object]:
    """Return the separately reviewed renderer contract for Windows 26.825."""

    component_anchor = (
        "function ZCc(e){let t=(0,QCc.c)(33),{accountIcon:n,accountLabel:r,"
        "additionalItems:i,displayName:a,identityItems:o,isPetVisible:s,"
        "onCopyUserId:c,onLogOut:l,onOpenProfile:u,onOpenSettings:d,"
        "onOpenWorkspaceSettings:f,onTogglePet:p,settingsShortcut:m,"
        "usageItems:h,workspaceSettingsRightIcon:g}=e"
    )
    app_server_anchor = (
        "function Pb(e,t){let n=e.get(Fb);if(n==null)throw Error("
        "`AppServerManager RPC is not connected`);return n.forHost(t)}"
    )
    reset_query = (
        "function idi(){let e=(0,fR.c)(1),t;return "
        "e[0]===Symbol.for(`react.memo_cache_sentinel`)?"
        "(t={queryKey:[`rate-limit-reset-credits`],queryFn:adi,"
        "refetchInterval:bx.ONE_MINUTE,staleTime:bx.FIVE_SECONDS},"
        "e[0]=t):t=e[0],Tx(t)}"
    )
    reset_query_replacement = (
        "function idi(){let e=window.__codexMuxResetAccountId;return "
        "Tx({queryKey:[`rate-limit-reset-credits`,e??`primary`],"
        "queryFn:e?()=>codexMuxRateLimitResets(e):adi,"
        "refetchInterval:bx.ONE_MINUTE,staleTime:bx.FIVE_SECONDS})}"
    )
    reset_mutation = (
        "function odi(){let e=(0,fR.c)(3),t=Sx(),n=bD(),r;return "
        "e[0]!==n||e[1]!==t?(r={mutationFn:sdi,onSuccess:(e,r)=>{"
        "let{creditId:i}=r,a=e.code;if(a===`reset`||a===`already_redeemed`){"
        "let n=e.code===`reset`?e.credit?.id??i:i;"
        "t.setQueryData([`rate-limit-reset-credits`],e=>Aui(e,a,n))}"
        "Promise.all([n([`rate-limit-status`]),"
        "n([`rate-limit-reset-credits`])])}},e[0]=n,e[1]=t,e[2]=r):"
        "r=e[2],Dx(r)}"
    )
    reset_mutation_replacement = (
        "function odi(){let e=Sx(),t=bD(),n=window.__codexMuxResetAccountId,"
        "r=[`rate-limit-reset-credits`,n??`primary`];return Dx({"
        "mutationFn:n?i=>codexMuxConsumeRateLimitReset(n,i):sdi,"
        "onSuccess:(a,o)=>{let{creditId:i}=o,c=a.code;"
        "if(c===`reset`||c===`already_redeemed`){let n=c===`reset`?"
        "a.credit?.id??i:i;e.setQueryData(r,e=>Aui(e,c,n))}"
        "Promise.all([t([`rate-limit-status`]),t(r)])}})}"
    )
    usage_header = (
        "_e=(0,SQ.jsx)(SR,{title:(0,SQ.jsx)(Iz,{asChild:!0,"
        "children:(0,SQ.jsx)(`h2`,{className:`m-0`,children:(0,SQ.jsx)(J,{"
        "id:`codex.rateLimitResetPromptModal.usageTrackingHeading`,"
        "defaultMessage:`Usage`,description:`Heading for the Codex usage limit modal`"
        "})})})}),"
    )
    usage_header_replacement = (
        "_e=(0,SQ.jsxs)(SQ.Fragment,{children:["
        "(0,SQ.jsx)(SR,{title:(0,SQ.jsx)(Iz,{asChild:!0,"
        "children:(0,SQ.jsx)(`h2`,{className:`m-0`,children:(0,SQ.jsx)(J,{"
        "id:`codex.rateLimitResetPromptModal.usageTrackingHeading`,"
        "defaultMessage:`Usage`,description:`Heading for the Codex usage limit modal`"
        "})})})}),globalThis.__codexMuxResetAccountSelector??null]}),"
    )
    plugin_mappings = (
        {
            "name": "list-installed-apps RPC mapping",
            "current": "Pb(e,n).sendRequest(`app/installed`,t?{forceRefresh:!0}:{})",
            "replacement": (
                "Pb(e,n).sendRequest(`app/installed`,"
                'codexMuxScopePluginRequest("list-installed-apps",t?{forceRefresh:!0}:{}))'
            ),
        },
        {
            "name": "read-apps RPC mapping",
            "current": "Pb(e,n).sendRequest(`app/read`,{appIds:t})",
            "replacement": (
                "Pb(e,n).sendRequest(`app/read`,"
                'codexMuxScopePluginRequest("read-apps",{appIds:t}))'
            ),
        },
        {
            "name": "list-apps RPC mapping",
            "current": (
                "Pb(e,n).sendRequest(`app/list`,{cursor:i,limit:tsr,"
                "forceRefetch:t},{trace:a})"
            ),
            "replacement": (
                "Pb(e,n).sendRequest(`app/list`,"
                'codexMuxScopePluginRequest("list-apps",{cursor:i,limit:tsr,forceRefetch:t}),'
                "{trace:a})"
            ),
        },
        {
            "name": "login-mcp-server RPC mapping",
            "current": "t.sendRequest(`mcpServer/oauth/login`,e)",
            "replacement": (
                't.sendRequest(`mcpServer/oauth/login`,'
                'codexMuxScopePluginRequest("login-mcp-server",e))'
            ),
        },
        {
            "name": "list-mcp-server-status RPC mapping",
            "current": (
                "Pb(e,t).listMcpServers({cursor:i,detail:n,limit:100},"
                "r===void 0?void 0:{trace:r})"
            ),
            "replacement": (
                "Pb(e,t).listMcpServers("
                'codexMuxScopePluginRequest("list-mcp-server-status",{cursor:i,detail:n,limit:100}),'
                "r===void 0?void 0:{trace:r})"
            ),
        },
        {
            "name": "listMcpServers RPC wrapper",
            "current": (
                "listMcpServers(e,t){let n=JSON.stringify({options:t,params:e}),"
                "r=this.mcpServerStatusPromises.get(n);if(r)return r;"
                "let i=this.sendRequest(`mcpServerStatus/list`,e,t);"
            ),
            "replacement": (
                "listMcpServers(e,t){let n=JSON.stringify({options:t,params:e}),"
                "r=this.mcpServerStatusPromises.get(n);if(r)return r;"
                "let i=this.sendRequest(`mcpServerStatus/list`,e,t);"
            ),
        },
        {
            "name": "mcpServerStatus/list RPC call",
            "current": "this.sendRequest(`mcpServerStatus/list`,e,t)",
            "replacement": "this.sendRequest(`mcpServerStatus/list`,e,t)",
        },
    )
    return {
        "variant_id": "windows-26.825",
        "build_6662": False,
        "component_anchor": component_anchor,
        "component_replacements": {
            "e7": "l8",
            "kXc": "swc",
            "Lo": "A_",
            "BW": "ZL",
            "QLs": "GCo",
            "_H": "cz",
            "S2": "vF",
            "CH": "mz",
            "jLa": "KLo",
        },
        "rpc_wrapper": "",
        "status_rpc_wrapper": "",
        "app_server_anchor": app_server_anchor,
        "app_server_replacement": app_server_anchor,
        "profile_query": "async function Mbc(){let e=await dS.safeGet(`/wham/profiles/me`)",
        "usage_modal": "function GCo(e){let t=(0,KCo.c)(20),{defaultResetCreditsOpen:n,initialAvailableCount:r,isRateLimitReached:i,onClose:a,onResetComplete:o}=e",
        "reset_query": reset_query,
        "reset_query_replacement": reset_query_replacement,
        "reset_mutation": reset_mutation,
        "reset_mutation_replacement": reset_mutation_replacement,
        "usage_header": usage_header,
        "usage_header_replacement": usage_header_replacement,
        "usage_slot": "usageItems:h",
        "usage_slot_replacement": (
            "usageItems:(globalThis.__codexMuxAccountMenuInjected=true,"
            "(0,l8.jsx)(CodexMuxAccountMenu,{}))"
        ),
        "open_change": (
            "open:s,side:`top`,sideOffset:6,triggerButton:Ot,onOpenChange:c,children:[N,null]",
        ),
        "open_name": "c",
        "open_preserved": "open:s,onOpenChange:c,contentWidth:`panel`,triggerButton:Ot",
        "profile_avatar": (
            "avatar:(0,$.jsxs)($.Fragment,{children:[(0,$.jsxs)(`label`,"
            '{"aria-disabled":B.isPending,className:Wt(`group relative flex size-20 '
            "rounded-full outline-none focus-within:ring-1 focus-within:ring-ring`,"
        ),
        "profile_avatar_replacement": (
            "avatar:(0,$.jsxs)($.Fragment,{children:["
            "globalThis.CodexMuxProfileAvatarStack?.({onSelect:()=>I.refetch()})??null,"
            "(0,$.jsxs)(`label`,{\"aria-disabled\":B.isPending,"
            "className:Wt(globalThis.CodexMuxProfileAvatarStack?`hidden`:"
            "`group relative flex size-20 rounded-full outline-none "
            "focus-within:ring-1 focus-within:ring-ring`,"
        ),
        "profile_name": (
            "displayName:ze??(0,$.jsx)(q,{id:`profile.nameFallback`,"
            "defaultMessage:`ChatGPT user`,description:`Fallback profile display name`})"
        ),
        "profile_name_replacement": (
            "displayName:globalThis.__codexMuxSelectedProfileAccountId?"
            "ze??(0,$.jsx)(q,{id:`profile.nameFallback`,"
            "defaultMessage:`ChatGPT user`,description:`Fallback profile display name`}):null"
        ),
        "profile_identity": (
            "username:Re==null?null:(0,$.jsx)(q,{id:`profile.usernameValue`,"
            "defaultMessage:`@{username}`,description:`Profile username shown with an at-sign prefix`,"
            "values:{username:Re}})"
        ),
        "profile_identity_replacement": (
            "username:globalThis.__codexMuxSelectedProfileAccountId&&Re!=null?"
            "(0,$.jsx)(q,{id:`profile.usernameValue`,"
            "defaultMessage:`@{username}`,description:`Profile username shown with an at-sign prefix`,"
            "values:{username:Re}}):null"
        ),
        "plugin_anchor": "contentAfterConnected:(0,$.jsxs)($.Fragment,{children:[",
        "plugin_replacement": (
            "contentAfterConnected:(0,$.jsxs)($.Fragment,{children:["
            "globalThis.CodexMuxPluginScope?.()??null,"
        ),
        "plugin_glob": "plugins-page-*.js",
        "thread_anchor": "function WT(e){let t=(0,JT.c)(58),",
        "thread_summary_anchor": (
            "(0,XT.jsx)(X.Section,{sectionKey:`tool-sources`,after:V,title:H,"
            "titleSuffix:U,children:W})"
        ),
        "thread_component_replacements": {},
        "thread_route": "xt(wa)",
        "thread_react": "YT",
        "thread_jsx": "XT",
        "thread_section": "X",
        "summary_component": "XT",
        "thread_conversation_id": "c",
        "plugin_mappings": plugin_mappings,
    }


def _variant_fingerprints(values: dict[str, object]) -> tuple[str, ...]:
    return (
        str(values["component_anchor"]),
        str(values["app_server_anchor"]),
        str(values["profile_query"]),
        str(values["usage_modal"]),
        str(values["reset_query"]),
        str(values["reset_mutation"]),
        str(values["usage_slot"]),
        str(values["open_change"][0]),
    )


def renderer_variant_template(variant_id: str) -> dict[str, object]:
    """Return a test/fixture template without pretending it selected a build."""
    if variant_id == "windows-26.820":
        return dict(_windows_26_820_renderer_values())
    if variant_id == "windows-26.825":
        return dict(_windows_26_825_renderer_values())
    if variant_id == "electron-6662":
        values = _legacy_renderer_variant_values("function Icl(e){let t=(0,Vcl.c)(248),")
        values["variant_id"] = variant_id
        return values
    if variant_id == "electron-original":
        values = _legacy_renderer_variant_values("fixture")
        values["variant_id"] = variant_id
        return values
    raise ValueError(f"unknown renderer variant template: {variant_id}")


def _renderer_variants() -> tuple[RendererVariant, ...]:
    original = renderer_variant_template("electron-original")
    renamed = renderer_variant_template("electron-6662")
    windows_26_820 = renderer_variant_template("windows-26.820")
    windows_26_825 = renderer_variant_template("windows-26.825")
    return (
        RendererVariant(
            "windows-26.820",
            WINDOWS_26_820_PACKAGE_NAME,
            WINDOWS_26_820_PACKAGE_VERSION,
            WINDOWS_26_820_ASAR_SHA256,
            _variant_fingerprints(windows_26_820),
            windows_26_820,
        ),
        RendererVariant(
            "windows-26.825",
            WINDOWS_26_825_PACKAGE_NAME,
            WINDOWS_26_825_PACKAGE_VERSION,
            WINDOWS_26_825_ASAR_SHA256,
            _variant_fingerprints(windows_26_825),
            windows_26_825,
        ),
        RendererVariant(
            "electron-6662",
            None,
            None,
            None,
            _variant_fingerprints(renamed),
            renamed,
        ),
        RendererVariant(
            "electron-original",
            None,
            None,
            None,
            _variant_fingerprints(original),
            original,
        ),
    )


RENDERER_VARIANTS = _renderer_variants()


def select_renderer_variant(
    bundle: str,
    *,
    package_name: str | None = None,
    package_version: str | None = None,
    app_asar_sha256: str | None = None,
) -> RendererVariant:
    """Select one exact renderer contract using metadata and multiple fingerprints."""
    package_name = None if package_name in {None, "", "unknown"} else package_name
    package_version = None if package_version in {None, "", "unknown"} else package_version
    app_asar_sha256 = None if app_asar_sha256 in {None, ""} else app_asar_sha256
    matches: list[RendererVariant] = []
    for variant in RENDERER_VARIANTS:
        if variant.package_name is not None and package_name is not None and package_name != variant.package_name:
            continue
        if variant.package_version is not None and package_version is not None and package_version != variant.package_version:
            continue
        if variant.app_asar_sha256 is not None and app_asar_sha256 is not None and app_asar_sha256.casefold() != variant.app_asar_sha256:
            continue
        if all(bundle.count(fingerprint) == 1 for fingerprint in variant.fingerprints):
            matches.append(variant)
    if len(matches) == 1:
        return matches[0]
    metadata = {
        "package_name": package_name,
        "package_version": package_version,
        "app_asar_sha256": app_asar_sha256,
    }
    if len(matches) > 1:
        raise RuntimeError(
            f"renderer variant selection is ambiguous: {[variant.variant_id for variant in matches]}"
        )
    raise RuntimeError(f"no renderer variant matched exact fingerprints: {metadata}")


def _renderer_variant_values(bundle: str) -> dict[str, object]:
    """Compatibility accessor that still requires exact multi-anchor selection."""
    return select_renderer_variant(bundle).values


def _observed_renderer_semantic_anchors(bundle: str) -> dict[str, str]:
    """Identify exact semantic counterparts seen in the acquired 26.820 build.

    These are audit evidence only. They deliberately do not make that build
    patchable: the replacement code still requires the historical exact
    anchors, and ``patch_renderer`` fails closed for every semantic change.
    """
    return {
        "native profile menu": (
            "function Jyl(e){let t=(0,Yyl.c)(33),{accountIcon:n,accountLabel:r,"
            "additionalItems:i,displayName:a,identityItems:o,isPetVisible:s,"
            "onCopyUserId:c,onLogOut:l,onOpenProfile:u,onOpenSettings:d,"
            "onOpenWorkspaceSettings:f,onTogglePet:p,settingsShortcut:m,"
            "usageItems:h,workspaceSettingsRightIcon:g}=e"
        ),
        "app-server request bridge": (
            "function qg(e,t){let n=e.get(Jg);if(n==null)throw Error("
            "`AppServerManager RPC is not connected`);return n.forHost(t)}"
        ),
        "profile statistics request": (
            "async function n2a(){let e=await Ob.safeGet(`/wham/profiles/me`);"
            "return{activityInsights:u2a(e.stats)"
        ),
        "native usage modal": (
            "function c6s(e){let t=(0,u6s.c)(28),{defaultResetCreditsOpen:n,"
            "errorMessage:r,initialAvailableCount:i,isResetting:a,onClose:o,"
            "onResetCredit:s}=e,{data:c}=lH(),{data:l}=J(BO),"
            "{data:u,isLoading:d}=WAa()"
        ),
        "reset-credit query": (
            "function WAa(){let e=(0,uH.c)(1),t;return e[0]==="
            "Symbol.for(`react.memo_cache_sentinel`)?(t={queryKey:["
            "`rate-limit-reset-credits`],queryFn:GAa"
        ),
        "reset-credit mutation": (
            "function KAa(){let e=(0,uH.c)(3),t=lt(),n=AS(),r;return "
            "e[0]!==n||e[1]!==t?(r={mutationFn:qAa"
        ),
        "usage sheet header": (
            "id:`codex.rateLimitResetPromptModal.usageTrackingHeading`,"
            "defaultMessage:`Usage`"
        ),
        "usage menu slot": "usageItems:wt",
        "list-apps RPC mapping": (
            "async function g9r({scope:e,forceRefetch:t,hostId:n}){try{"
            "let r=async(i,a)=>{let o=await qg(e,n).sendRequest(`app/list`"
        ),
        "list-installed-apps RPC mapping": (
            "async function h9r({scope:e,forceRefresh:t=!1,hostId:n}){try{"
            "let r=(await qg(e,n).sendRequest(`app/installed`"
        ),
        "read-apps RPC mapping": "qg(e,n).sendRequest(`app/read`,{appIds:t})",
        "login-mcp-server RPC mapping": "sendRequest(`mcpServer/oauth/login`,e)",
        "list-mcp-server-status RPC mapping": (
            "async function exn(e,t,n,r,i=null){let a=await qg(e,t).listMcpServers"
        ),
        "profile menu open-state hook 1": (
            "open:s,side:`top`,sideOffset:6,triggerButton:Ot,onOpenChange:l"
        ),
    }


def _observed_profile_semantic_anchors() -> dict[str, str]:
    """Exact profile-page counterparts found in the acquired renderer asset."""
    return {
        "Profile avatar": (
            'avatar:(0,$.jsxs)($.Fragment,{children:[(0,$.jsxs)(`label`,'
            '{"aria-disabled":I.isPending'
        ),
        "Profile display name": "displayName:Ye??(0,$.jsx)(J,{id:`profile.nameFallback`",
        "Profile username and plan": "username:qe==null?null:(0,$.jsx)(J,{id:`profile.usernameValue`",
    }


def _semantic_variant(text: str, name: str, asset: str, semantic: str | None) -> AnchorAudit:
    if semantic is None:
        return AnchorAudit(name, asset, "MISSING", None, 0)
    count = text.count(semantic)
    if count == 1:
        return AnchorAudit(name, asset, "SEMANTICALLY_CHANGED", "semantic", count)
    if count > 1:
        return AnchorAudit(name, asset, "AMBIGUOUS", "semantic", count)
    return AnchorAudit(name, asset, "MISSING", None, 0)


def _audit_windows_26_820(
    extracted: Path,
    index: str,
    bundle_path: Path,
    bundle: str,
    values: dict[str, object],
) -> list[AnchorAudit]:
    """Audit the exact 26.820 surfaces, including the moved thread summary."""
    assets = extracted / "webview" / "assets"
    audit: list[AnchorAudit] = [
        AnchorAudit(
            "renderer CSP",
            "webview/index.html",
            "UNCHANGED" if index.count("connect-src &#39;self&#39;") == 1 else "MISSING",
            "connect-src &#39;self&#39;" if index.count("connect-src &#39;self&#39;") == 1 else None,
            index.count("connect-src &#39;self&#39;"),
        )
    ]
    for name, key in (
        ("native profile menu", "component_anchor"),
        ("app-server request bridge", "app_server_anchor"),
        ("profile statistics request", "profile_query"),
        ("native usage modal", "usage_modal"),
        ("reset-credit query", "reset_query"),
        ("reset-credit mutation", "reset_mutation"),
        ("usage sheet header", "usage_header"),
        ("usage menu slot", "usage_slot"),
        ("profile menu open-state hook 1", "open_change"),
        ("profile menu outside open-state preservation", "open_preserved"),
    ):
        current = values[key]
        if key == "open_change":
            current = current[0]
        audit.append(_variant(bundle, name, bundle_path.name, str(current)))
    audit.append(_variant(bundle, "usage-window selection", bundle_path.name, "let y=v;if(g!=null){"))
    for spec in values["plugin_mappings"]:
        audit.append(_variant(bundle, str(spec["name"]), bundle_path.name, str(spec["current"])))
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
        audit.append(
            _variant(
                profile_text,
                name,
                profile_path.name if profile_path else "profile-*.js",
                str(values[key]),
            )
        )

    plugin_assets = list(assets.glob(str(values["plugin_glob"])))
    _, plugin_audit = _asset_with_anchor(
        plugin_assets,
        "Plugins settings content",
        str(values["plugin_glob"]),
        str(values["plugin_anchor"]),
    )
    audit.append(plugin_audit)

    thread_assets = list(assets.glob("local-conversation-thread-*.js"))
    thread_path, thread_audit = _asset_with_anchor(
        thread_assets,
        "thread summary source component",
        "local-conversation-thread-*.js",
        str(values["thread_anchor"]),
    )
    audit.append(thread_audit)
    thread_text = thread_path.read_text(encoding="utf-8") if thread_path else ""
    audit.append(
        _variant(
            thread_text,
            "thread summary insertion point",
            "local-conversation-thread-*.js",
            str(values["thread_summary_anchor"]),
        )
    )
    return audit


def _audit_windows_26_825(
    extracted: Path,
    index: str,
    bundle_path: Path,
    bundle: str,
    values: dict[str, object],
) -> list[AnchorAudit]:
    """Audit the exact 26.825 renderer contract after the compatibility refresh."""

    assets = extracted / "webview" / "assets"
    audit: list[AnchorAudit] = [
        AnchorAudit(
            "renderer CSP",
            "webview/index.html",
            "UNCHANGED" if index.count("connect-src &#39;self&#39;") == 1 else "MISSING",
            "connect-src &#39;self&#39;" if index.count("connect-src &#39;self&#39;") == 1 else None,
            index.count("connect-src &#39;self&#39;"),
        )
    ]
    for name, key in (
        ("native profile menu", "component_anchor"),
        ("app-server request bridge", "app_server_anchor"),
        ("profile statistics request", "profile_query"),
        ("native usage modal", "usage_modal"),
        ("reset-credit query", "reset_query"),
        ("reset-credit mutation", "reset_mutation"),
        ("usage sheet header", "usage_header"),
        ("usage menu slot", "usage_slot"),
        ("profile menu open-state hook 1", "open_change"),
        ("profile menu outside open-state preservation", "open_preserved"),
    ):
        current = values[key]
        if key == "open_change":
            current = current[0]
        audit.append(_variant(bundle, name, bundle_path.name, str(current)))
    audit.append(
        _variant(bundle, "usage-window selection", bundle_path.name, "let y=v;if(g!=null){")
    )
    for spec in values["plugin_mappings"]:
        audit.append(_variant(bundle, str(spec["name"]), bundle_path.name, str(spec["current"])))
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
        audit.append(
            _variant(
                profile_text,
                name,
                profile_path.name if profile_path else "profile-*.js",
                str(values[key]),
            )
        )

    plugin_assets = list(assets.glob(str(values["plugin_glob"])))
    _, plugin_audit = _asset_with_anchor(
        plugin_assets,
        "Plugins settings content",
        str(values["plugin_glob"]),
        str(values["plugin_anchor"]),
    )
    audit.append(plugin_audit)

    thread_assets = list(assets.glob("local-conversation-thread-*.js"))
    thread_path, thread_audit = _asset_with_anchor(
        thread_assets,
        "thread summary source component",
        "local-conversation-thread-*.js",
        str(values["thread_anchor"]),
    )
    audit.append(thread_audit)
    thread_text = thread_path.read_text(encoding="utf-8") if thread_path else ""
    audit.append(
        _variant(
            thread_text,
            "thread summary insertion point",
            "local-conversation-thread-*.js",
            str(values["thread_summary_anchor"]),
        )
    )
    return audit


def audit_renderer_anchors(
    extracted: Path,
    *,
    package_name: str | None = None,
    package_version: str | None = None,
    app_asar_sha256: str | None = None,
) -> list[AnchorAudit]:
    """Audit exact semantic hooks without changing the extracted ASAR."""
    webview = extracted / "webview"
    assets = webview / "assets"
    index_path = webview / "index.html"
    if not index_path.is_file():
        return [AnchorAudit("renderer CSP", "webview/index.html", "MISSING", None, 0)]
    index = index_path.read_text(encoding="utf-8")
    initial_bundles = list(assets.glob("app-initial-*.js"))
    if len(initial_bundles) != 1:
        return [AnchorAudit("initial renderer bundle", "webview/assets", "AMBIGUOUS", None, len(initial_bundles))]
    bundle_path = initial_bundles[0]
    bundle = bundle_path.read_text(encoding="utf-8")
    try:
        variant = select_renderer_variant(
            bundle,
            package_name=package_name,
            package_version=package_version,
            app_asar_sha256=app_asar_sha256,
        )
    except RuntimeError:
        variant = None
    if variant is not None and variant.variant_id == "windows-26.820":
        return _audit_windows_26_820(extracted, index, bundle_path, bundle, variant.values)
    if variant is not None and variant.variant_id == "windows-26.825":
        return _audit_windows_26_825(extracted, index, bundle_path, bundle, variant.values)
    values = variant.values if variant is not None else _legacy_renderer_variant_values(bundle)
    semantic_anchors = _observed_renderer_semantic_anchors(bundle)
    old_values = _legacy_renderer_variant_values(bundle.replace("function Icl(e){let t=(0,Vcl.c)(248),", "function wXc({sidebarFooter:e,triggerButton:t})"))
    build_6662 = bool(values["build_6662"])
    audit: list[AnchorAudit] = [
        AnchorAudit(
            "renderer CSP",
            "webview/index.html",
            "UNCHANGED" if index.count("connect-src &#39;self&#39;") == 1 else "MISSING",
            "connect-src &#39;self&#39;" if index.count("connect-src &#39;self&#39;") == 1 else None,
            index.count("connect-src &#39;self&#39;"),
        )
    ]
    def add_variant(
        name: str,
        current: str,
        renamed: str | None = None,
        *,
        prefer_semantic: bool = False,
    ) -> None:
        semantic = semantic_anchors.get(name)
        if prefer_semantic and semantic is not None and bundle.count(semantic) > 0:
            audit.append(_semantic_variant(bundle, name, bundle_path.name, semantic))
        else:
            audit.append(_variant(bundle, name, bundle_path.name, current, renamed, semantic))

    def add_key_variant(name: str, key: str) -> None:
        current = str(old_values[key] if build_6662 else values[key])
        renamed = str(values[key]) if build_6662 else None
        add_variant(name, current, renamed, prefer_semantic=name == "native usage modal")

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
                semantic_anchors.get(name),
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
                semantic_anchors.get(f"profile menu open-state hook {index + 1}"),
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
    profile_semantic_anchors = _observed_profile_semantic_anchors()
    for name, key in (
        ("Profile avatar", "profile_avatar"),
        ("Profile display name", "profile_name"),
        ("Profile username and plan", "profile_identity"),
    ):
        current = str(old_values[key] if build_6662 else values[key])
        renamed = str(values[key]) if build_6662 else None
        audit.append(
            _variant(
                profile_text,
                name,
                profile_path.name if profile_path else "profile-*.js",
                current,
                renamed,
                profile_semantic_anchors.get(name),
            )
        )

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
        if new_plugin_audit.status == "UNCHANGED" and old_plugin_audit.status == "MISSING":
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
        if new_thread_audit.status == "UNCHANGED" and old_thread_audit.status == "MISSING":
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


def _count_contract_anchor(extracted: Path, asset_glob: str, anchor: str) -> list[dict[str, object]]:
    """Return exact anchor locations for a read-only renderer comparison."""

    assets = sorted((extracted / "webview" / "assets").glob(asset_glob))
    locations: list[dict[str, object]] = []
    for asset in assets:
        count = asset.read_text(encoding="utf-8").count(anchor)
        if count:
            locations.append({"asset": asset.name, "count": count})
    return locations


def compare_renderer_contract(
    extracted: Path,
    reference_variant: str = "windows-26.820",
) -> dict[str, object]:
    """Compare an extracted renderer with a known contract without granting patch permission.

    The comparison intentionally uses only the extracted bytes and explicit
    contract templates.  It does not select a patch variant from package
    metadata, write files, or make a semantic match patchable.
    """

    reference = renderer_variant_template(reference_variant)
    webview = extracted / "webview"
    assets = webview / "assets"
    index_path = webview / "index.html"
    initial_bundles = sorted(assets.glob("app-initial-*.js"))
    result: dict[str, object] = {
        "reference_variant": reference_variant,
        "reference_fingerprint_count": len(_variant_fingerprints(reference)),
        "read_only": True,
        "patch_permission_granted": False,
        "patchable": False,
        "exact_fingerprint_matches": [],
        "exact_replacement_anchor_matches": [],
        "surface_status": [],
        "missing_anchors": [],
        "ambiguous_anchors": [],
        "semantic_changes": [],
        "asset_moves": [],
    }
    if not index_path.is_file() or len(initial_bundles) != 1:
        missing = result["missing_anchors"]
        assert isinstance(missing, list)
        missing.append(
            {
                "name": "initial renderer bundle",
                "asset": "webview/assets",
                "reason": "missing" if not initial_bundles else "expected exactly one bundle",
                "count": len(initial_bundles),
            }
        )
        return result

    index_html = index_path.read_text(encoding="utf-8")
    bundle_path = initial_bundles[0]
    bundle = bundle_path.read_text(encoding="utf-8")
    exact_fingerprints: list[dict[str, object]] = []
    for fingerprint_index, anchor in enumerate(_variant_fingerprints(reference)):
        count = bundle.count(anchor)
        item = {
            "index": fingerprint_index,
            "anchor": anchor,
            "asset": bundle_path.name,
            "count": count,
        }
        if count == 1:
            exact_fingerprints.append(item)
        elif count == 0:
            missing = result["missing_anchors"]
            assert isinstance(missing, list)
            missing.append({"name": f"fingerprint-{fingerprint_index + 1}", **item})
        else:
            ambiguous = result["ambiguous_anchors"]
            assert isinstance(ambiguous, list)
            ambiguous.append({"name": f"fingerprint-{fingerprint_index + 1}", **item})
    result["exact_fingerprint_matches"] = exact_fingerprints

    current = renderer_variant_template("windows-26.825")
    surfaces: list[tuple[str, str, str, str, str]] = [
        ("renderer CSP", "webview/index.html", "connect-src &#39;self&#39;", "connect-src &#39;self&#39;", "unchanged"),
        ("native profile menu", "app-initial", str(reference["component_anchor"]), str(current["component_anchor"]), "renamed"),
        ("app-server request bridge", "app-initial", str(reference["app_server_anchor"]), str(current["app_server_anchor"]), "renamed"),
        ("profile statistics request", "app-initial", str(reference["profile_query"]), str(current["profile_query"]), "renamed"),
        ("native usage modal", "app-initial", str(reference["usage_modal"]), str(current["usage_modal"]), "semantically_changed"),
        ("reset-credit query", "app-initial", str(reference["reset_query"]), str(current["reset_query"]), "semantically_changed"),
        ("reset-credit mutation", "app-initial", str(reference["reset_mutation"]), str(current["reset_mutation"]), "semantically_changed"),
        ("usage sheet header", "app-initial", str(reference["usage_header"]), str(current["usage_header"]), "semantically_changed"),
        ("usage menu slot", "app-initial", str(reference["usage_slot"]), str(current["usage_slot"]), "renamed"),
        ("app/list", "app-initial", str(reference["plugin_mappings"][2]["current"]), str(current["plugin_mappings"][2]["current"]), "renamed"),
        ("app/installed", "app-initial", str(reference["plugin_mappings"][0]["current"]), str(current["plugin_mappings"][0]["current"]), "renamed"),
        ("app/read", "app-initial", str(reference["plugin_mappings"][1]["current"]), str(current["plugin_mappings"][1]["current"]), "renamed"),
        ("mcpServer/oauth/login", "app-initial", str(reference["plugin_mappings"][3]["current"]), str(current["plugin_mappings"][3]["current"]), "unchanged"),
        ("mcpServerStatus/list", "app-initial", str(reference["plugin_mappings"][4]["current"]), str(current["plugin_mappings"][4]["current"]), "renamed"),
        ("listMcpServers wrapper", "app-initial", str(reference["plugin_mappings"][5]["current"]), str(current["plugin_mappings"][5]["current"]), "unchanged"),
        ("mcpServerStatus/list RPC call", "app-initial", str(reference["plugin_mappings"][6]["current"]), str(current["plugin_mappings"][6]["current"]), "unchanged"),
        ("usage-window selection", "app-initial", "let y=v;if(g!=null){", "let y=v;if(g!=null){", "unchanged"),
        ("profile menu open-state hook", "app-initial", str(reference["open_change"][0]), str(current["open_change"][0]), "renamed"),
        ("profile menu outside open-state preservation", "app-initial", str(reference["open_preserved"]), str(current["open_preserved"]), "renamed"),
        ("subscription depletion alert", "app-initial", "defaultMessage:`You’re out of Codex and Work usage`", "defaultMessage:`You’re out of Codex and Work usage`", "unchanged"),
        ("Profile avatar", "profile-*.js", str(reference["profile_avatar"]), str(current["profile_avatar"]), "renamed"),
        ("Profile display name", "profile-*.js", str(reference["profile_name"]), str(current["profile_name"]), "renamed"),
        ("Profile username and plan", "profile-*.js", str(reference["profile_identity"]), str(current["profile_identity"]), "renamed"),
        ("Plugins settings content", str(reference["plugin_glob"]), str(reference["plugin_anchor"]), str(current["plugin_anchor"]), "asset_moved"),
        ("thread summary source component", "local-conversation-thread-*.js", str(reference["thread_anchor"]), str(current["thread_anchor"]), "renamed"),
        ("thread summary insertion point", "local-conversation-thread-*.js", str(reference["thread_summary_anchor"]), str(current["thread_summary_anchor"]), "semantically_changed"),
    ]
    exact_replacements: list[dict[str, object]] = []
    surface_status: list[dict[str, object]] = []
    for name, asset_label, old_anchor, new_anchor, changed_kind in surfaces:
        if asset_label == "webview/index.html":
            old_locations = [{"asset": index_path.name, "count": index_html.count(old_anchor)}]
            new_locations = old_locations
        elif asset_label == "app-initial":
            old_locations = [{"asset": bundle_path.name, "count": bundle.count(old_anchor)}]
            new_locations = [{"asset": bundle_path.name, "count": bundle.count(new_anchor)}]
        else:
            old_locations = _count_contract_anchor(extracted, asset_label, old_anchor)
            new_locations = _count_contract_anchor(extracted, asset_label, new_anchor)
        old_count = sum(int(item["count"]) for item in old_locations)
        new_count = sum(int(item["count"]) for item in new_locations)
        if old_count == 1:
            status = "UNCHANGED"
            exact_replacements.append(
                {"name": name, "asset": asset_label, "anchor": old_anchor, "count": old_count}
            )
        elif old_count > 1:
            status = "AMBIGUOUS"
        elif new_count == 1:
            status = {
                "renamed": "RENAMED",
                "semantically_changed": "SEMANTICALLY_CHANGED",
                "asset_moved": "MOVED",
                "unchanged": "UNCHANGED",
            }[changed_kind]
        elif new_count > 1:
            status = "AMBIGUOUS"
        else:
            status = "MISSING"
        entry = {
            "name": name,
            "asset": asset_label,
            "status": status,
            "reference_anchor": old_anchor,
            "observed_anchor": new_anchor if new_count else None,
            "reference_count": old_count,
            "observed_count": new_count,
            "observed_assets": new_locations,
        }
        surface_status.append(entry)
        if status == "MISSING":
            missing = result["missing_anchors"]
            assert isinstance(missing, list)
            missing.append(entry)
        elif status == "AMBIGUOUS":
            ambiguous = result["ambiguous_anchors"]
            assert isinstance(ambiguous, list)
            ambiguous.append(entry)
        elif status == "SEMANTICALLY_CHANGED":
            semantic_changes = result["semantic_changes"]
            assert isinstance(semantic_changes, list)
            semantic_changes.append(entry)
        elif status == "MOVED":
            asset_moves = result["asset_moves"]
            assert isinstance(asset_moves, list)
            asset_moves.append(entry)
    result["exact_replacement_anchor_matches"] = exact_replacements
    result["surface_status"] = surface_status
    host_scoped = next(
        (item for item in surface_status if item["name"] == "app-server request bridge"),
        None,
    )
    result["host_scoped_rpc"] = {
        "reference": str(reference["app_server_anchor"]),
        "observed": str(current["app_server_anchor"]),
        "status": host_scoped["status"] if host_scoped is not None else "MISSING",
        "read_only": True,
    }
    return result


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


def _patch_legacy_renderer(
    extracted: Path,
    token: str,
    variant: RendererVariant,
    audit: list[AnchorAudit],
) -> list[AnchorAudit]:
    """Patch the two historical renderer contracts."""
    values = variant.values
    build_6662 = bool(values["build_6662"])
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
    bundle = bundle.replace(
        usage_modal_anchor,
        usage_modal_anchor.replace("{", "{CodexMuxUseResetAccountState();", 1),
        1,
    )

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
    thread_component = thread_component.replace(
        "__CODEX_MUX_ROUTE__", "jf(Pa)" if build_6662 else "$n(sr)"
    )
    thread_component = thread_component.replace(
        "__CODEX_MUX_REACT__", "jy" if build_6662 else "TE"
    )
    thread_component = thread_component.replace(
        "__CODEX_MUX_JSX__", "CE" if build_6662 else "zE"
    )
    thread_component = thread_component.replace(
        "__CODEX_MUX_SECTION__", "q" if build_6662 else "K"
    )
    _require_unique(thread, str(values["thread_anchor"]), "could not find the native thread summary sources component")
    thread = thread.replace(str(values["thread_anchor"]), thread_component + "\n" + str(values["thread_anchor"]), 1)
    summary_anchor = "children:[c,l,u,d,f,p,m,h,g,_,v,y,b,x]"
    _require_unique(thread, summary_anchor, "could not find the native thread summary section list")
    thread = thread.replace(summary_anchor, "children:[c,l,u,d,f,(0," + str(values["summary_component"]) + ".jsx)(CodexMuxThreadSubscription,{}),p,m,h,g,_,v,y,b,x]", 1)
    thread_path.write_text(thread, encoding="utf-8")
    return audit


def _patch_windows_26_820_renderer(
    extracted: Path,
    token: str,
    variant: RendererVariant,
    audit: list[AnchorAudit],
) -> list[AnchorAudit]:
    """Patch the exact 26.820 renderer contract with fail-closed replacements."""
    values = variant.values
    webview = extracted / "webview"
    index_path = webview / "index.html"
    index = index_path.read_text(encoding="utf-8")
    connect_anchor = "connect-src &#39;self&#39;"
    _require_unique(index, connect_anchor, "could not find ChatGPT renderer CSP connect-src")
    index_path.write_text(
        index.replace(connect_anchor, f"{connect_anchor} http://127.0.0.1:{CONTROL_PORT}", 1),
        encoding="utf-8",
    )

    assets = webview / "assets"
    initial_bundles = list(assets.glob("app-initial-*.js"))
    if len(initial_bundles) != 1:
        raise RuntimeError(f"expected one ChatGPT initial renderer bundle, found {len(initial_bundles)}")
    bundle_path = initial_bundles[0]
    bundle = bundle_path.read_text(encoding="utf-8")
    if "function CodexMuxAccountMenu(" in bundle:
        raise RuntimeError("source app already contains the Codex multiplexer menu")

    component = (PROJECT_ROOT / "ui" / "account-menu.js").read_text(encoding="utf-8")
    component = component.replace("__CODEX_MUX_CONTROL_PORT__", str(CONTROL_PORT))
    component = component.replace("__CODEX_MUX_CONTROL_TOKEN__", token)
    component = replace_javascript_identifiers(
        component,
        dict(values["component_replacements"]),
    )
    component_anchor = str(values["component_anchor"])
    _require_unique(bundle, component_anchor, "could not find the native ChatGPT profile menu component")
    bundle = bundle.replace(component_anchor, component + "\n" + component_anchor, 1)

    app_server_anchor = str(values["app_server_anchor"])
    _require_unique(bundle, app_server_anchor, "could not find the native app-server request bridge")
    # qg(scope, hostId) is deliberately left host-scoped. Account routing is
    # added only to the explicit plugin parameter objects below.
    bundle = bundle.replace(app_server_anchor, str(values["app_server_replacement"]), 1)

    for spec in values["plugin_mappings"]:
        current = str(spec["current"])
        replacement = str(spec["replacement"])
        _require_unique(bundle, current, f"could not verify the native {spec['name']}")
        bundle = bundle.replace(current, replacement, 1)

    profile_query_anchor = str(values["profile_query"])
    _require_unique(bundle, profile_query_anchor, "could not find the native profile stats request")
    bundle = bundle.replace(
        profile_query_anchor,
        "let e=await codexMuxProfileData(globalThis.__codexMuxSelectedProfileAccountId??null)",
        1,
    )

    usage_modal_anchor = str(values["usage_modal"])
    _require_unique(bundle, usage_modal_anchor, "could not find the native Usage modal component")
    bundle = bundle.replace(
        usage_modal_anchor,
        usage_modal_anchor.replace("{", "{CodexMuxUseResetAccountState();", 1),
        1,
    )

    reset_query_anchor = str(values["reset_query"])
    _require_unique(bundle, reset_query_anchor, "could not find the native reset-credit query")
    reset_query_replacement = (
        "function WAa(){let e=window.__codexMuxResetAccountId;return "
        "Lt({queryKey:[`rate-limit-reset-credits`,e??`primary`],"
        "queryFn:e?()=>codexMuxRateLimitResets(e):GAa,"
        "refetchInterval:nm.ONE_MINUTE,staleTime:nm.FIVE_SECONDS})}"
    )
    bundle = bundle.replace(reset_query_anchor, reset_query_replacement, 1)

    reset_mutation_anchor = str(values["reset_mutation"])
    _require_unique(bundle, reset_mutation_anchor, "could not find the native reset-credit mutation")
    reset_mutation_replacement = (
        "function KAa(){let e=lt(),t=AS(),n=window.__codexMuxResetAccountId,"
        "r=[`rate-limit-reset-credits`,n??`primary`];return $t({"
        "mutationFn:n?i=>codexMuxConsumeRateLimitReset(n,i):qAa,"
        "onSuccess:(a,o)=>{let{creditId:s}=o,c=a.code;"
        "if(c===`reset`||c===`already_redeemed`){let n=c===`reset`?"
        "a.credit?.id??s:s;e.setQueryData(r,e=>gAa(e,c,n))}"
        "Promise.all([t([`rate-limit-status`]),t(r)])}})}"
    )
    bundle = bundle.replace(reset_mutation_anchor, reset_mutation_replacement, 1)

    selected_usage_anchor = "let y=v;if(g!=null){"
    _require_unique(bundle, selected_usage_anchor, "could not find the native usage-window selection")
    bundle = bundle.replace(
        selected_usage_anchor,
        "let y=window.__codexMuxSelectedUsageWindows??v;if(g!=null){",
        1,
    )
    usage_header_anchor = str(values["usage_header"])
    _require_unique(bundle, usage_header_anchor, "could not find the native Usage sheet header")
    bundle = bundle.replace(
        usage_header_anchor,
        str(values["usage_header_replacement"]),
        1,
    )
    usage_anchor = str(values["usage_slot"])
    _require_unique(bundle, usage_anchor, "could not find the native ChatGPT usage menu slot")
    bundle = bundle.replace(usage_anchor, str(values["usage_slot_replacement"]), 1)

    for anchor in values["open_change"]:
        _require_unique(bundle, anchor, "could not find the native profile menu open-state hook")
        open_name = str(values["open_name"])
        bundle = bundle.replace(
            anchor,
            anchor.replace(
                f"onOpenChange:{open_name}",
                f"onOpenChange:CodexMuxProfileMenuOpenChange({open_name})",
            ),
            1,
        )
    for depleted_anchor in (
        "defaultMessage:`You’re out of Codex and Work usage`",
        "defaultMessage:`You’ve used all Codex and Work usage`",
        "defaultMessage:`You’ve reached your usage limit`",
    ):
        _require_unique(bundle, depleted_anchor, "could not find a native subscription depletion alert")
        bundle = bundle.replace(
            depleted_anchor,
            "defaultMessage:`All connected subscriptions are depleted`",
            1,
        )
    bundle_path.write_text(bundle, encoding="utf-8")

    profile_assets = list(assets.glob("profile-*.js"))
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

    plugin_assets = list(assets.glob(str(values["plugin_glob"])))
    plugin_path = _require_asset(
        plugin_assets,
        str(values["plugin_anchor"]),
        "could not find the native Plugins settings bundle",
    )
    plugin = plugin_path.read_text(encoding="utf-8")
    _require_unique(plugin, str(values["plugin_anchor"]), "could not find the native Plugins settings content")
    plugin_path.write_text(
        plugin.replace(str(values["plugin_anchor"]), str(values["plugin_replacement"]), 1),
        encoding="utf-8",
    )

    thread_assets = list(assets.glob("local-conversation-thread-*.js"))
    thread_path = _require_asset(
        thread_assets,
        str(values["thread_anchor"]),
        "could not find the exact 26.820 local conversation renderer bundle",
    )
    thread = thread_path.read_text(encoding="utf-8")
    thread_component = (PROJECT_ROOT / "ui" / "thread-subscription.js").read_text(encoding="utf-8")
    thread_component = thread_component.replace("__CODEX_MUX_CONTROL_PORT__", str(CONTROL_PORT))
    thread_component = thread_component.replace("__CODEX_MUX_CONTROL_TOKEN__", token)
    thread_component = thread_component.replace("__CODEX_MUX_ROUTE__", str(values["thread_route"]))
    thread_component = thread_component.replace("__CODEX_MUX_REACT__", str(values["thread_react"]))
    thread_component = thread_component.replace("__CODEX_MUX_JSX__", str(values["thread_jsx"]))
    thread_component = thread_component.replace("__CODEX_MUX_SECTION__", str(values["thread_section"]))
    _require_unique(thread, str(values["thread_anchor"]), "could not find the exact 26.820 thread component anchor")
    thread = thread.replace(str(values["thread_anchor"]), thread_component + "\n" + str(values["thread_anchor"]), 1)
    summary_anchor = str(values["thread_summary_anchor"])
    _require_unique(thread, summary_anchor, "could not find the exact 26.820 thread summary insertion point")
    summary_replacement = (
        "(0,aE.jsxs)(aE.Fragment,{children:["
        + summary_anchor
        + ",(0,aE.jsx)(CodexMuxThreadSubscription,{conversationId:a})]})"
    )
    thread = thread.replace(summary_anchor, summary_replacement, 1)
    thread_path.write_text(thread, encoding="utf-8")
    return audit


def _patch_windows_26_825_renderer(
    extracted: Path,
    token: str,
    variant: RendererVariant,
    audit: list[AnchorAudit],
) -> list[AnchorAudit]:
    """Patch the separately reviewed Windows 26.825 renderer contract."""

    values = variant.values
    webview = extracted / "webview"
    index_path = webview / "index.html"
    index = index_path.read_text(encoding="utf-8")
    connect_anchor = "connect-src &#39;self&#39;"
    _require_unique(index, connect_anchor, "could not find ChatGPT renderer CSP connect-src")
    index_path.write_text(
        index.replace(connect_anchor, f"{connect_anchor} http://127.0.0.1:{CONTROL_PORT}", 1),
        encoding="utf-8",
    )

    assets = webview / "assets"
    initial_bundles = list(assets.glob("app-initial-*.js"))
    if len(initial_bundles) != 1:
        raise RuntimeError(f"expected one ChatGPT initial renderer bundle, found {len(initial_bundles)}")
    bundle_path = initial_bundles[0]
    bundle = bundle_path.read_text(encoding="utf-8")
    if "function CodexMuxAccountMenu(" in bundle:
        raise RuntimeError("source app already contains the Codex multiplexer menu")

    component = (PROJECT_ROOT / "ui" / "account-menu.js").read_text(encoding="utf-8")
    component = component.replace("__CODEX_MUX_CONTROL_PORT__", str(CONTROL_PORT))
    component = component.replace("__CODEX_MUX_CONTROL_TOKEN__", token)
    component = replace_javascript_identifiers(
        component,
        dict(values["component_replacements"]),
    )
    component_anchor = str(values["component_anchor"])
    _require_unique(bundle, component_anchor, "could not find the native ChatGPT profile menu component")
    bundle = bundle.replace(component_anchor, component + "\n" + component_anchor, 1)

    app_server_anchor = str(values["app_server_anchor"])
    _require_unique(bundle, app_server_anchor, "could not find the native app-server request bridge")
    bundle = bundle.replace(app_server_anchor, str(values["app_server_replacement"]), 1)

    for spec in values["plugin_mappings"]:
        current = str(spec["current"])
        replacement = str(spec["replacement"])
        _require_unique(bundle, current, f"could not verify the native {spec['name']}")
        bundle = bundle.replace(current, replacement, 1)

    profile_query_anchor = str(values["profile_query"])
    _require_unique(bundle, profile_query_anchor, "could not find the native profile stats request")
    bundle = bundle.replace(
        profile_query_anchor,
        "async function Mbc(){let e=await codexMuxProfileData(globalThis.__codexMuxSelectedProfileAccountId??null)",
        1,
    )

    usage_modal_anchor = str(values["usage_modal"])
    _require_unique(bundle, usage_modal_anchor, "could not find the native Usage modal component")
    bundle = bundle.replace(
        usage_modal_anchor,
        usage_modal_anchor.replace("{", "{CodexMuxUseResetAccountState();", 1),
        1,
    )

    reset_query_anchor = str(values["reset_query"])
    _require_unique(bundle, reset_query_anchor, "could not find the native reset-credit query")
    bundle = bundle.replace(reset_query_anchor, str(values["reset_query_replacement"]), 1)

    reset_mutation_anchor = str(values["reset_mutation"])
    _require_unique(bundle, reset_mutation_anchor, "could not find the native reset-credit mutation")
    bundle = bundle.replace(
        reset_mutation_anchor,
        str(values["reset_mutation_replacement"]),
        1,
    )

    selected_usage_anchor = "let y=v;if(g!=null){"
    _require_unique(bundle, selected_usage_anchor, "could not find the native usage-window selection")
    bundle = bundle.replace(
        selected_usage_anchor,
        "let y=window.__codexMuxSelectedUsageWindows??v;if(g!=null){",
        1,
    )
    usage_header_anchor = str(values["usage_header"])
    _require_unique(bundle, usage_header_anchor, "could not find the native Usage sheet header")
    bundle = bundle.replace(
        usage_header_anchor,
        str(values["usage_header_replacement"]),
        1,
    )
    usage_anchor = str(values["usage_slot"])
    _require_unique(bundle, usage_anchor, "could not find the native ChatGPT usage menu slot")
    bundle = bundle.replace(usage_anchor, str(values["usage_slot_replacement"]), 1)

    for anchor in values["open_change"]:
        _require_unique(bundle, anchor, "could not find the native profile menu open-state hook")
        open_name = str(values["open_name"])
        bundle = bundle.replace(
            anchor,
            anchor.replace(
                f"onOpenChange:{open_name}",
                f"onOpenChange:CodexMuxProfileMenuOpenChange({open_name})",
            ),
            1,
        )
    for depleted_anchor in (
        "defaultMessage:`You’re out of Codex and Work usage`",
        "defaultMessage:`You’ve used all Codex and Work usage`",
        "defaultMessage:`You’ve reached your usage limit`",
    ):
        _require_unique(bundle, depleted_anchor, "could not find a native subscription depletion alert")
        bundle = bundle.replace(
            depleted_anchor,
            "defaultMessage:`All connected subscriptions are depleted`",
            1,
        )
    bundle_path.write_text(bundle, encoding="utf-8")

    profile_assets = list(assets.glob("profile-*.js"))
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

    plugin_assets = list(assets.glob(str(values["plugin_glob"])))
    plugin_path = _require_asset(
        plugin_assets,
        str(values["plugin_anchor"]),
        "could not find the native Plugins settings bundle",
    )
    plugin = plugin_path.read_text(encoding="utf-8")
    _require_unique(plugin, str(values["plugin_anchor"]), "could not find the native Plugins settings content")
    plugin_path.write_text(
        plugin.replace(str(values["plugin_anchor"]), str(values["plugin_replacement"]), 1),
        encoding="utf-8",
    )

    thread_assets = list(assets.glob("local-conversation-thread-*.js"))
    thread_path = _require_asset(
        thread_assets,
        str(values["thread_anchor"]),
        "could not find the exact 26.825 local conversation renderer bundle",
    )
    thread = thread_path.read_text(encoding="utf-8")
    thread_component = (PROJECT_ROOT / "ui" / "thread-subscription.js").read_text(encoding="utf-8")
    thread_component = thread_component.replace("__CODEX_MUX_CONTROL_PORT__", str(CONTROL_PORT))
    thread_component = thread_component.replace("__CODEX_MUX_CONTROL_TOKEN__", token)
    thread_component = thread_component.replace("__CODEX_MUX_ROUTE__", str(values["thread_route"]))
    thread_component = thread_component.replace("__CODEX_MUX_REACT__", str(values["thread_react"]))
    thread_component = thread_component.replace("__CODEX_MUX_JSX__", str(values["thread_jsx"]))
    thread_component = thread_component.replace("__CODEX_MUX_SECTION__", str(values["thread_section"]))
    _require_unique(thread, str(values["thread_anchor"]), "could not find the exact 26.825 thread component anchor")
    thread = thread.replace(str(values["thread_anchor"]), thread_component + "\n" + str(values["thread_anchor"]), 1)
    summary_anchor = str(values["thread_summary_anchor"])
    _require_unique(thread, summary_anchor, "could not find the exact 26.825 thread summary insertion point")
    summary_component = str(values["summary_component"])
    summary_replacement = (
        f"(0,{summary_component}.jsxs)({summary_component}.Fragment,{{children:["
        + summary_anchor
        + f",(0,{summary_component}.jsx)(CodexMuxThreadSubscription,{{conversationId:{values['thread_conversation_id']}}})]}})"
    )
    thread = thread.replace(summary_anchor, summary_replacement, 1)
    thread_path.write_text(thread, encoding="utf-8")
    return audit


def patch_renderer(
    extracted: Path,
    token: str,
    *,
    package_name: str | None = None,
    package_version: str | None = None,
    app_asar_sha256: str | None = None,
) -> list[AnchorAudit]:
    """Patch renderer account/routing surfaces after exact semantic validation."""
    audit = audit_renderer_anchors(
        extracted,
        package_name=package_name,
        package_version=package_version,
        app_asar_sha256=app_asar_sha256,
    )
    failed_audit = [
        item
        for item in audit
        if item.status in {"MISSING", "SEMANTICALLY_CHANGED", "AMBIGUOUS"}
    ]
    if failed_audit:
        details = "; ".join(
            f"{item.name}: {item.status} ({item.asset})" for item in failed_audit
        )
        raise RuntimeError(f"renderer anchor audit failed: {details}")
    webview = extracted / "webview"
    initial_bundles = list((webview / "assets").glob("app-initial-*.js"))
    if len(initial_bundles) != 1:
        raise RuntimeError(f"expected one ChatGPT initial renderer bundle, found {len(initial_bundles)}")
    bundle = initial_bundles[0].read_text(encoding="utf-8")
    variant = select_renderer_variant(
        bundle,
        package_name=package_name,
        package_version=package_version,
        app_asar_sha256=app_asar_sha256,
    )
    if variant.variant_id == "windows-26.820":
        return _patch_windows_26_820_renderer(extracted, token, variant, audit)
    if variant.variant_id == "windows-26.825":
        return _patch_windows_26_825_renderer(extracted, token, variant, audit)
    return _patch_legacy_renderer(extracted, token, variant, audit)


def sha256(path: Path) -> str:
    """Hash a generated artifact without reading any credential-bearing files."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
