"""TLS/SSL context randomization for JA3/JA4 evasion."""

from __future__ import annotations
import ssl
import random
from itertools import cycle
from threading import Lock

_tls_pool = None
_tls_pool_lock = Lock()


def _build_tls_pool():
    pools = []
    pools.append(
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
    )
    try:
        test = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        test.set_ciphers("ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305")
        pools.append(
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
        )
        pools.append(
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
        )
    except Exception:
        pass
    pools.append(
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-GCM-SHA384"
    )
    return pools


class TLSRandomizer:
    _pool = None

    @classmethod
    def get_ssl_context(cls) -> ssl.SSLContext:
        if cls._pool is None:
            global _tls_pool
            if _tls_pool is None:
                with _tls_pool_lock:
                    if _tls_pool is None:
                        _tls_pool = cycle(_build_tls_pool())
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.options |= ssl.OP_NO_COMPRESSION
        except Exception:
            pass
        try:
            with _tls_pool_lock:
                ciphers = next(_tls_pool)
            ctx.set_ciphers(ciphers)
        except Exception:
            with ssl.suppress(Exception):
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        return ctx
