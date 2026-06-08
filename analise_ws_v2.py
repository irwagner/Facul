"""
Captura mais frames do WebSocket com cenarios distintos:
  1. Conexao default e captura ate 10 frames
  2. Envia ServerAuth invalido pra ver erro
  3. Envia varios handlerType pra mapear comandos
  4. Decodifica o "msg" base64 do frame inicial e tenta interpretar como protobuf

Tambem extrai do message.js:
  - Lista completa de cmd ids (handlerType numericos)
  - Mapping handlerType -> nome de mensagem
"""
from __future__ import annotations

import asyncio
import base64
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

import websockets


def decode_proto(blob: bytes, max_fields: int = 30) -> list:
    """Tenta extrair fields protobuf a partir de bytes."""
    out = []
    i = 0
    count = 0
    while i < len(blob) and count < max_fields:
        if blob[i] == 0:
            i += 1
            continue
        first = blob[i]
        field_num = first >> 3
        wire_type = first & 0x7
        i += 1
        if wire_type == 2:
            if i >= len(blob):
                break
            length = blob[i]
            i += 1
            if i + length > len(blob):
                break
            value = blob[i:i + length]
            try:
                txt = value.decode("utf-8")
                if all(c.isprintable() or c in ("\t", "\n") for c in txt):
                    out.append({"field": field_num, "type": "string", "value": txt})
                else:
                    out.append({"field": field_num, "type": "bytes", "hex": value.hex()})
            except Exception:
                out.append({"field": field_num, "type": "bytes", "hex": value.hex()})
            i += length
        elif wire_type == 0:
            value = 0
            shift = 0
            while i < len(blob):
                b = blob[i]
                value |= (b & 0x7F) << shift
                i += 1
                if not (b & 0x80):
                    break
                shift += 7
            out.append({"field": field_num, "type": "varint", "value": value})
        elif wire_type == 5:
            out.append({"field": field_num, "type": "fixed32", "value": int.from_bytes(blob[i:i + 4], "little")})
            i += 4
        elif wire_type == 1:
            out.append({"field": field_num, "type": "fixed64", "value": int.from_bytes(blob[i:i + 8], "little")})
            i += 8
        else:
            break
        count += 1
    return out


async def capture(uri: str, *, max_frames: int = 10, timeout: float = 25.0):
    print(f"\n  conectando em {uri}")
    frames = []
    try:
        async with websockets.connect(
            uri,
            origin="https://ds.amizade777.com",
            ping_interval=None,
            close_timeout=2,
        ) as ws:
            try:
                deadline = asyncio.get_event_loop().time() + timeout
                while len(frames) < max_frames:
                    remaining = max(0.5, deadline - asyncio.get_event_loop().time())
                    if remaining <= 0:
                        break
                    msg = await asyncio.wait_for(ws.recv(), timeout=remaining)
                    if isinstance(msg, str):
                        frames.append(("text", msg))
                        print(f"    [text] {len(msg)} chars: {msg[:200]}")
                    else:
                        frames.append(("bytes", msg))
                        print(f"    [bytes] {len(msg)}: hex={msg[:64].hex()}")
            except asyncio.TimeoutError:
                pass
            except Exception as exc:
                print(f"    erro recv: {exc}")
    except Exception as exc:
        print(f"  erro: {type(exc).__name__}: {exc}")
    return frames


def parse_initial_msg_payload(text_msg: str) -> dict:
    """Tenta interpretar {msgtype:1, msg:base64, errcode:null}."""
    try:
        obj = json.loads(text_msg)
    except Exception:
        return {"raw": text_msg, "error": "not json"}
    out = {"json": obj}
    msg = obj.get("msg")
    if isinstance(msg, str):
        try:
            decoded = base64.b64decode(msg)
            out["msg_b64_decoded_hex"] = decoded.hex()
            out["msg_b64_decoded_size"] = len(decoded)
            # Tenta protobuf
            fields = decode_proto(decoded)
            out["msg_b64_protobuf_fields"] = fields
        except Exception as exc:
            out["msg_b64_error"] = str(exc)
    return out


def extract_protobuf_handlerids() -> dict:
    """Procura mapeamento handlerType -> nome de mensagem em message.js."""
    target = next((f for f in (ROOT / "bundles").iterdir() if "message.js" in f.name and "ds" in f.name), None)
    if not target:
        return {}
    text = target.read_text(encoding="utf-8", errors="replace")
    print(f"\n  message.js: {len(text)} chars")

    # Procurar definicoes do tipo: HandlerType = { LOGIN: 1, BET: 2, ... }
    enum_blocks = re.findall(r"(?:HandlerType|HandlerCode|MessageType|CmdType|CommandType)\s*=\s*\{([^}]{50,4000})\}", text)
    cmd_map = {}
    for block in enum_blocks:
        for m in re.finditer(r'(?:["\']?)(\w+)(?:["\']?)\s*[:=]\s*(\d+)', block):
            cmd_map[m.group(1)] = int(m.group(2))
    print(f"  enum blocks: {len(enum_blocks)}, cmd_map size: {len(cmd_map)}")

    # Padrao mais flexivel:
    # values[1] = "LOGIN" e [LOGIN] = 1
    pairs_a = re.findall(r"values\[(\d+)\]\s*=\s*[\"'](\w{3,40})[\"']", text)
    pairs_b = re.findall(r"\[\s*[\"'](\w{3,40})[\"']\s*\]\s*=\s*(\d+)", text)
    print(f"  pares values[i]=name: {len(pairs_a)}, pares [name]=i: {len(pairs_b)}")

    # protobufjs gera blocos como: 
    # HandlerType.values[HandlerType.LOGIN = 1] = "LOGIN";
    pj_pattern = re.findall(r"\b(\w+)\s*\.values\[\s*\w+\.(\w+)\s*=\s*(\d+)\s*\]\s*=\s*[\"']\2[\"']", text)
    print(f"  protobufjs enum entries: {len(pj_pattern)}")

    enum_by_class: dict = {}
    for cls, name, num in pj_pattern:
        enum_by_class.setdefault(cls, {})[name] = int(num)

    return {
        "enum_classes": enum_by_class,
        "raw_pairs_a": pairs_a[:50],
        "raw_pairs_b": pairs_b[:50],
        "cmd_map": cmd_map,
    }


async def main():
    print("=" * 70)
    print("WS CAPTURE + PROTO ENUMERATION")
    print("=" * 70)
    frames = await capture("wss://ds.amizade777.com/websocket6")
    print(f"\n  total {len(frames)} frames")

    # Decodificar primeiro frame se for JSON
    first_payload = None
    for kind, msg in frames:
        if kind == "text":
            first_payload = parse_initial_msg_payload(msg)
            print("\n  primeiro frame text decodificado:")
            print(json.dumps(first_payload, indent=2, default=str)[:1500])
            break

    # Mapeamento handlerType
    enum = extract_protobuf_handlerids()
    if enum.get("enum_classes"):
        print("\n  Enum classes encontradas no message.js:")
        for cls, mapping in list(enum["enum_classes"].items())[:5]:
            print(f"\n    {cls}:")
            for name, num in sorted(mapping.items(), key=lambda x: x[1])[:30]:
                print(f"      {num:>4}  {name}")

    Path("analise_ws_v2.json").write_text(
        json.dumps({
            "frames_count": len(frames),
            "first_payload": first_payload,
            "enum": enum,
        }, indent=2, default=str, ensure_ascii=False),
        encoding="utf-8",
    )
    print("\n  Salvo em analise_ws_v2.json")


if __name__ == "__main__":
    asyncio.run(main())
