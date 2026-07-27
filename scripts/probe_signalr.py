"""Sanitized live probe for the Whisker Ting SignalR endpoint.

This script is intended to run inside a Home Assistant container. It reuses the
configured Ting credentials without printing them and reports only protocol
metadata, message shapes, and voltage-like numeric values.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import aiohttp
import msgpack

from custom_components.whisker_ting.api import WhiskerApiClient
from custom_components.whisker_ting.const import SIGNALR_URL

CONFIG_ENTRIES_PATH = Path("/config/.storage/core.config_entries")
RECORD_SEPARATOR = "\x1e"


def encode_varint(value: int) -> bytes:
    """Encode a non-negative integer using SignalR's 7-bit VarInt format."""
    encoded = bytearray()
    while True:
        part = value & 0x7F
        value >>= 7
        if value:
            part |= 0x80
        encoded.append(part)
        if not value:
            return bytes(encoded)


def frame_messagepack(payload: Any) -> bytes:
    """Serialize and frame one MessagePack hub message."""
    body = msgpack.packb(payload, use_bin_type=True)
    return encode_varint(len(body)) + body


def iter_signalr_frames(data: bytes) -> Iterable[bytes]:
    """Yield complete SignalR binary frames from one WebSocket message."""
    offset = 0
    while offset < len(data):
        length = 0
        shift = 0
        for prefix_length in range(1, 6):
            if offset >= len(data):
                raise ValueError("incomplete SignalR length prefix")
            part = data[offset]
            offset += 1
            length |= (part & 0x7F) << shift
            if not part & 0x80:
                break
            shift += 7
        else:
            raise ValueError("SignalR length prefix exceeds five bytes")

        end = offset + length
        if end > len(data):
            raise ValueError(
                f"incomplete SignalR frame: declared={length}, available={len(data) - offset}"
            )
        yield data[offset:end]
        offset = end


def describe(value: Any, depth: int = 0) -> Any:
    """Describe a decoded value without exposing account strings or tokens."""
    if depth >= 5:
        return type(value).__name__
    if isinstance(value, dict):
        return {
            "type": "map",
            "keys": sorted(str(key) for key in value),
            "values": {
                str(key): describe(item, depth + 1)
                for key, item in value.items()
                if not isinstance(item, str)
            },
        }
    if isinstance(value, (list, tuple)):
        return {
            "type": "array",
            "length": len(value),
            "items": [describe(item, depth + 1) for item in value],
        }
    if isinstance(value, bytes):
        return {
            "type": "bytes",
            "length": len(value),
            "prefix_hex": value[:32].hex(),
        }
    if isinstance(value, str):
        return {"type": "string", "length": len(value)}
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return type(value).__name__


def summarize_hub_message(message: Any) -> dict[str, Any]:
    """Return a safe summary of a decoded SignalR hub message."""
    if not isinstance(message, list) or not message:
        return {"kind": "invalid", "shape": describe(message)}

    message_type = message[0]
    summary: dict[str, Any] = {
        "message_type": message_type,
        "field_count": len(message),
    }
    if message_type == 1 and len(message) >= 5:
        summary["kind"] = "invocation"
        summary["target"] = message[3]
        summary["arguments"] = describe(message[4])
    elif message_type == 3 and len(message) >= 4:
        summary["kind"] = "completion"
        summary["invocation_id"] = message[2]
        summary["result_kind"] = message[3]
        if len(message) >= 5:
            summary["result"] = describe(message[4])
    elif message_type == 6:
        summary["kind"] = "ping"
    elif message_type == 7:
        summary["kind"] = "close"
        summary["error"] = message[1] if len(message) >= 2 else None
        summary["allow_reconnect"] = message[2] if len(message) >= 3 else None
    else:
        summary["kind"] = "other"
        summary["shape"] = describe(message)
    return summary


def configured_credentials() -> tuple[str, str]:
    """Load the configured Ting username/password from Home Assistant storage."""
    storage = json.loads(CONFIG_ENTRIES_PATH.read_text(encoding="utf-8"))
    entries = [
        entry
        for entry in storage["data"]["entries"]
        if entry.get("domain") == "whisker_ting"
    ]
    if len(entries) != 1:
        raise RuntimeError(f"expected one Ting config entry, found {len(entries)}")
    data = entries[0]["data"]
    return data["username"], data["password"]


def invocation_packet(variant: str, arguments: list[Any]) -> bytes:
    """Build an InitializeStreaming invocation using the requested wire shape."""
    invocation = [1, {}, "probe-1", "InitializeStreaming", arguments]
    if variant == "legacy":
        return msgpack.packb({1: invocation}, use_bin_type=True)
    if variant == "framed5":
        return frame_messagepack(invocation)
    if variant == "framed6":
        return frame_messagepack([*invocation, []])
    raise ValueError(f"unknown variant: {variant}")


async def probe(variant: str, seconds: float) -> None:
    """Authenticate, subscribe, and print sanitized server responses."""
    username, password = configured_credentials()
    async with aiohttp.ClientSession() as session:
        client = WhiskerApiClient(session, username, password)
        devices = await client.get_all_device_states()
        if not devices:
            raise RuntimeError("Ting account has no devices")
        device = next(iter(devices.values()))
        if not device.station_id or not client.api_key or not client.user_id:
            raise RuntimeError("Ting account is missing stream credentials")

        print(
            json.dumps(
                {
                    "variant": variant,
                    "device_count": len(devices),
                    "station_id_length": len(device.station_id),
                    "api_key_length": len(client.api_key),
                    "user_id_type": type(client.user_id).__name__,
                    "user_id_digits": len(str(client.user_id)),
                },
                sort_keys=True,
            )
        )

        arguments = [
            {
                "StationId": device.station_id,
                "DataElement": "ComboBinaryData",
            },
            client.api_key,
            str(client.user_id),
        ]

        async with session.ws_connect(
            SIGNALR_URL,
            headers={"Origin": "ionic://localhost"},
        ) as websocket:
            await websocket.send_str(
                json.dumps({"protocol": "messagepack", "version": 1}) + RECORD_SEPARATOR
            )
            handshake = await websocket.receive(timeout=10)
            print(
                json.dumps(
                    {
                        "handshake_type": handshake.type.name,
                        "handshake_data": handshake.data
                        if isinstance(handshake.data, str)
                        else describe(handshake.data),
                    },
                    sort_keys=True,
                )
            )

            packet = invocation_packet(variant, arguments)
            print(
                json.dumps(
                    {
                        "sent_bytes": len(packet),
                        "sent_prefix_hex": packet[:8].hex(),
                    },
                    sort_keys=True,
                )
            )
            await websocket.send_bytes(packet)

            deadline = asyncio.get_running_loop().time() + seconds
            while asyncio.get_running_loop().time() < deadline:
                timeout = max(0.1, deadline - asyncio.get_running_loop().time())
                try:
                    response = await websocket.receive(timeout=timeout)
                except asyncio.TimeoutError:
                    break

                if response.type == aiohttp.WSMsgType.BINARY:
                    print(
                        json.dumps(
                            {
                                "received_bytes": len(response.data),
                                "received_prefix_hex": response.data[:16].hex(),
                            },
                            sort_keys=True,
                        )
                    )
                    try:
                        for frame in iter_signalr_frames(response.data):
                            decoded = msgpack.unpackb(
                                frame,
                                raw=False,
                                strict_map_key=False,
                            )
                            print(
                                json.dumps(
                                    summarize_hub_message(decoded),
                                    sort_keys=True,
                                )
                            )
                    except (
                        ValueError,
                        msgpack.UnpackException,
                    ) as err:
                        print(
                            json.dumps(
                                {
                                    "decode_error": str(err),
                                    "raw_shape": describe(response.data),
                                },
                                sort_keys=True,
                            )
                        )
                elif response.type == aiohttp.WSMsgType.TEXT:
                    print(
                        json.dumps(
                            {"received_text": response.data},
                            sort_keys=True,
                        )
                    )
                else:
                    print(
                        json.dumps(
                            {
                                "websocket_event": response.type.name,
                                "extra": response.extra,
                            },
                            sort_keys=True,
                        )
                    )
                    if response.type in {
                        aiohttp.WSMsgType.CLOSE,
                        aiohttp.WSMsgType.CLOSED,
                        aiohttp.WSMsgType.ERROR,
                    }:
                        break


def main() -> None:
    """Run the probe."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--variant",
        choices=("legacy", "framed5", "framed6"),
        default="framed6",
    )
    parser.add_argument("--seconds", type=float, default=10.0)
    args = parser.parse_args()
    asyncio.run(probe(args.variant, args.seconds))


if __name__ == "__main__":
    main()
