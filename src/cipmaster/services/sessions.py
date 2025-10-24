"""Session-related helpers used by the CLI."""

from __future__ import annotations

from cipmaster.cip import session as cip_session


class SessionService:
    """Adapter around :mod:`cipmaster.cip.session`."""

    def create_session(self, *args, **kwargs):
        return cip_session.CIPSession(*args, **kwargs)

    def __getattr__(self, item):
        return getattr(cip_session, item)


__all__ = ["SessionService"]
