"""
Analise do WebSocket /websocket6:
  1. Conecta sem auth e grava primeiros frames protobuf
  2. Procura no message.js onde 'sign' eh calculado e o que entra no input
  3. Tenta decodificar primeiros bytes de cada frame (varint protobuf)
"""
from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

import websockets


async def capture_ws_frames(uri: str, *, max_frames: int = 5, timeout: float = 25.0):
    print(f"\n  conectando em {uri}")
    frames: list[bytes] = []
    try:
        async with websockets.connect(
            uri,
            origin="https://ds.amizade777.com",
            user_agent_header="Mozilla/5.0",
            ping_interval=None,
            close_timeout=2,
            max_size=10 * 1024 * 1024,
        ) as ws:
            print(f"  conectado, esperando ate {timeout}s pra capturar {max_frames} frames")
            try:
                deadline = asyncio.get_event_loop().time() + timeout
                while len(frames) < max_frames:
                    remaining = max(0.5, deadline - asyncio.get_event_loop().time())
                    if remaining <= 0:
                        break
                    msg = await asyncio.wait_for(ws.recv(), timeout=remaining)
                    if isinstance(msg, str):
                        msg = msg.encode()
                    frames.append(msg)
                    print(f"    frame {len(frames)}: {len(msg)} bytes  hex={msg[:64].hex()}")
            except asyncio.TimeoutError:
                print(f"  timeout depois de capturar {len(frames)} frames")
            except Exception as exc:
                print(f"  erro durante recv: {type(exc).__name__}: {exc}")
            # Tenta enviar um heartbeat fake pra ver resposta
            print("\n  enviando ping/pong proto fake (8 bytes 0x00)")
            try:
                await ws.send(b"\x00" * 8)
                msg = await asyncio.wait_for(ws.recv(), timeout=5)
                print(f"    resposta: {len(msg)} bytes  hex={msg[:64].hex() if isinstance(msg, bytes) else msg[:80]!r}")
                frames.append(msg if isinstance(msg, bytes) else msg.encode())
            except Exception as exc:
                print(f"    sem resposta ou erro: {exc}")
    except Exception as exc:
        print(f"  ERRO ao conectar: {type(exc).__name__}: {exc}")
    return frames


def decode_protobuf_preview(blob: bytes) -> str:
    """Tenta listar field tags + tipos do proto sem ter o schema."""
    out_lines = []
    i = 0
    field_count = 0
    while i < len(blob) and field_count < 30:
        # Varint: bits 7
        # Field tag = (field_number << 3) | wire_type
        first = blob[i]
        if first == 0:
            break
        field_num = first >> 3
        wire_type = first & 0x7
        i += 1
        wire_name = {0: "varint", 1: "fixed64", 2: "length", 5: "fixed32"}.get(wire_type, "?")
        if wire_type == 2:
            if i >= len(blob):
                break
            length = blob[i]
            i += 1
            if i + length > len(blob):
                break
            value_preview = blob[i:i + length]
            try:
                txt = value_preview.decode("utf-8")
                if all(c.isprintable() or c.isspace() for c in txt):
                    out_lines.append(f"  field {field_num} ({wire_name}, len {length}): {txt!r}")
                else:
                    out_lines.append(f"  field {field_num} ({wire_name}, len {length}): hex={value_preview[:24].hex()}")
            except Exception:
                out_lines.append(f"  field {field_num} ({wire_name}, len {length}): hex={value_preview[:24].hex()}")
            i += length
        elif wire_type == 0:
            # Le varint
            value = 0
            shift = 0
            while i < len(blob):
                b = blob[i]
                value |= (b & 0x7F) << shift
                i += 1
                if not (b & 0x80):
                    break
                shift += 7
                if shift > 63:
                    break
            out_lines.append(f"  field {field_num} (varint): {value}")
        elif wire_type == 5:
            value = int.from_bytes(blob[i:i + 4], "little")
            out_lines.append(f"  field {field_num} (fixed32): {value}")
            i += 4
        elif wire_type == 1:
            value = int.from_bytes(blob[i:i + 8], "little")
            out_lines.append(f"  field {field_num} (fixed64): {value}")
            i += 8
        else:
            break
        field_count += 1
    return "\n".join(out_lines) if out_lines else "  (sem fields decodificaveis)"


def find_sign_logic_in_message_js() -> dict:
    print("\n[2/3] PROCURANDO LOGICA DE SIGN NO message.js")
    bundle_dir = ROOT / "bundles"
    target = next((f for f in bundle_dir.iterdir() if "message.js" in f.name and "ds" in f.name), None)
    if not target:
        return {"error": "message.js nao encontrado"}
    text = target.read_text(encoding="utf-8", errors="replace")
    print(f"  arquivo: {target.name} ({len(text)} chars)")

    out = {}

    # Procurar contexto ao redor de cada uso de 'sign'
    # Padrao: function (...) { ...sign... }
    sign_funcs = []
    for m in re.finditer(r"(\w+)\s*\.sign\s*=\s*function\s*\(([^)]{0,200})\)\s*\{", text):
        sign_funcs.append({
            "object": m.group(1),
            "args": m.group(2),
            "position": m.start(),
        })
    for m in re.finditer(r"sign\s*[:=]\s*function\s*\(([^)]{0,200})\)\s*\{", text):
        sign_funcs.append({
            "object": "?",
            "args": m.group(1),
            "position": m.start(),
        })
    print(f"\n  Funcoes 'sign' definidas: {len(sign_funcs)}")
    out["sign_funcs"] = sign_funcs[:20]

    # Procurar md5(...) com algumas variaveis dentro
    md5_calls = re.findall(r"md5\s*\(\s*([^)]{1,200})\)", text, re.IGNORECASE)
    print(f"  Chamadas md5(): {len(md5_calls)}")
    for c in md5_calls[:10]:
        print(f"    md5({c[:120]})")
    out["md5_calls"] = md5_calls[:20]

    # Snippets ao redor de "sign" com 200 chars de contexto
    print("\n  Trechos com 'sign' (primeiros 5):")
    snippets = []
    for i, m in enumerate(re.finditer(r"\bsign\b", text)):
        if i >= 8:
            break
        start = max(0, m.start() - 200)
        end = min(len(text), m.end() + 200)
        snippet = text[start:end].replace("\n", " ")
        # so quer onde ele eh atribuido ou setado
        if any(kw in snippet for kw in ("=", ":", ".sign(")):
            print(f"    [{m.start()}] ...{snippet[:300]}...")
            print()
            snippets.append({"position": m.start(), "snippet": snippet[:600]})
    out["sign_snippets"] = snippets

    # Procurar o time + something pattern (heartbeat sign)
    heartbeat_re = re.compile(r'msgtype\s*:\s*3\s*[,;}]')
    hits = list(heartbeat_re.finditer(text))
    print(f"\n  Referencias a msgtype:3 (heartbeat): {len(hits)}")
    for h in hits[:3]:
        start = max(0, h.start() - 300)
        end = min(len(text), h.end() + 300)
        print(f"    pos {h.start()}: {text[start:end].replace(chr(10), ' ')[:600]}")

    return out


async def main():
    print("=" * 70)
    print("[1/3] CAPTURA DE FRAMES DO WEBSOCKET (sem auth)")
    print("=" * 70)
    frames = await capture_ws_frames("wss://ds.amizade777.com/websocket6", max_frames=5, timeout=20)
    print(f"\n  capturados {len(frames)} frames")
    print("\n[2/3] DECODE PROTOBUF DOS FRAMES CAPTURADOS")
    print("=" * 70)
    for i, f in enumerate(frames):
        print(f"\n  frame {i} ({len(f)} bytes):")
        print(decode_protobuf_preview(f))

    out = find_sign_logic_in_message_js()
    
    Path("analise_ws.json").write_text(
        __import__("json").dumps({
            "frames_captured": len(frames),
            "frame_sizes": [len(f) for f in frames],
            "frame_hex_first_64": [f[:64].hex() for f in frames],
            "sign_analysis": out,
        }, indent=2, default=str),
        encoding="utf-8",
    )
    print("\n  Salvo em analise_ws.json")


if __name__ == "__main__":
    asyncio.run(main())
