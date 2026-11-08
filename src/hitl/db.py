from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib import resources
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool


def migrate(url: str) -> None:
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(resources.files("hitl").joinpath("schema.sql").read_text())


class Database:
    def __init__(self, url: str, min_size: int = 2, max_size: int = 10):
        self.url = url
        self.pool = AsyncConnectionPool(url, min_size=min_size, max_size=max_size, open=False, kwargs={"options": "-c timezone=UTC"})

    async def open(self) -> None:
        await self.pool.open(wait=True, timeout=30)

    async def close(self) -> None:
        await self.pool.close()

    @asynccontextmanager
    async def tx(self) -> AsyncIterator[psycopg.AsyncCursor[dict[str, Any]]]:
        async with self.pool.connection() as conn, conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
            yield cur
