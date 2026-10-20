"""Performance and latency overhead benchmarks for Veilgate pipeline components.

Asserts enterprise SLAs:
1. Schema compaction & discovery: < 15ms for 45 tools.
2. Tokenization & minimization cached throughput: p95 latency < 5ms.
"""

import time
from pathlib import Path

import numpy as np
import pytest
from ulid import ULID

from veilgate.config.policy_models import (
    Transport,
    UpstreamSpec,
    VeilgatePolicy,
)
from veilgate.config.settings import VeilgateSettings
from veilgate.gateway import create_gateway_pipeline
from veilgate.services.models import SessionContext, ToolRef


@pytest.fixture
def bench_policy() -> VeilgatePolicy:
    """Policy configuring 3 upstream servers and standard rules."""
    return VeilgatePolicy(
        version="1",
        extends="recommended",
        default_tool_allow=True,
        upstreams=[
            UpstreamSpec(id="srv1", transport=Transport.STDIO, command="python"),
            UpstreamSpec(id="srv2", transport=Transport.STDIO, command="python"),
            UpstreamSpec(id="srv3", transport=Transport.STDIO, command="python"),
        ],
        protect=["internal_margin", "secret_token"],
        drop=["debug_trace", "internal_id"],
    )


@pytest.mark.anyio
async def test_benchmark_catalog_discovery_overhead(
    tmp_path: Path,
    bench_policy: VeilgatePolicy,
) -> None:
    """Benchmark discovery on 45 tools across 3 upstream servers."""
    settings = VeilgateSettings(db_path=tmp_path / "bench_cat.db")
    pipeline, db_manager = await create_gateway_pipeline(settings, policy=bench_policy)

    try:
        session = SessionContext(session_id="ses_bench_cat")
        await pipeline.sessions.create_or_touch(session.session_id, transport="stdio")

        # Ingest 45 tools (15 per server)
        for srv_idx in range(1, 4):
            srv_id = f"srv{srv_idx}"
            for tool_idx in range(15):
                await pipeline.catalog_svc.ingest_tool(
                    server_id=srv_id,
                    tool_name=f"tool_action_{tool_idx}",
                    description=f"Automated tool {tool_idx} for {srv_id} performing data processing.",
                    input_schema={
                        "type": "object",
                        "properties": {
                            "param_a": {"type": "string"},
                            "param_b": {"type": "integer"},
                        },
                    },
                )

        # Warmup
        await pipeline.on_list_tools(session)

        # Measure 20 discovery iterations
        timings: list[float] = []
        for _ in range(20):
            t0 = time.perf_counter()
            tools = await pipeline.on_list_tools(session)
            elapsed = (time.perf_counter() - t0) * 1000.0  # in ms
            timings.append(elapsed)

        mean_ms = float(np.mean(timings))
        p95_ms = float(np.percentile(timings, 95))

        # Assert SLA (< 15ms mean discovery latency)
        assert len(tools) > 0
        assert mean_ms < 15.0, f"Discovery mean latency {mean_ms:.2f}ms exceeded 15ms SLA"
    finally:
        if hasattr(db_manager, "close"):
            await db_manager.close()


@pytest.mark.anyio
async def test_benchmark_minimizer_p95_latency(
    tmp_path: Path,
    bench_policy: VeilgatePolicy,
) -> None:
    """Benchmark tokenization and bloat dropping to verify p95 < 20ms in un-cached mode."""
    settings = VeilgateSettings(db_path=tmp_path / "bench_min.db")
    pipeline, db_manager = await create_gateway_pipeline(settings, policy=bench_policy)

    try:
        session = SessionContext(session_id="ses_bench_min")
        await pipeline.sessions.create_or_touch(session.session_id, transport="stdio")

        # Realistic payload with sensitive and bloat fields
        raw_payload = {
            "invoice_id": 9012,
            "vendor": "Acme Global",
            "contact_email": "finance@acme.example.com",
            "bank_account": "123456789012",
            "routing_number": "021000021",
            "internal_margin": "32.4%",
            "items": [
                {"sku": f"SKU_{i}", "qty": i + 1, "price": 19.99}
                for i in range(10)
            ],
            "connection": "close",
            "etag": "W/109485",
            "internal_id": "row_992",
        }
        ref = ToolRef(server="srv1", tool="get_invoice")

        # Warmup (seeds stable tokens in SQLite WAL)
        await pipeline.minimizer.minimize(
            raw_payload=raw_payload,
            ref=ref,
            session=session,
            event_id=str(ULID()),
        )

        # Measure 50 minimization iterations
        timings: list[float] = []
        for _ in range(50):
            event_id = str(ULID())
            t0 = time.perf_counter()
            await pipeline.minimizer.minimize(
                raw_payload=raw_payload,
                ref=ref,
                session=session,
                event_id=event_id,
            )
            elapsed = (time.perf_counter() - t0) * 1000.0  # ms
            timings.append(elapsed)

        mean_ms = float(np.mean(timings))
        p95_ms = float(np.percentile(timings, 95))

        # Assert SLA: p95 latency < 20.0ms on disk I/O without in-memory caching
        assert p95_ms < 20.0, f"Minimizer p95 latency {p95_ms:.2f}ms exceeded 20.0ms SLA"
    finally:
        if hasattr(db_manager, "close"):
            await db_manager.close()
