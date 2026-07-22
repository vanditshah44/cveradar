"""Stale sync-run reaping."""
from datetime import timedelta

from app.services import sync_runs


class _Result:
    def __init__(self, rowcount):
        self.rowcount = rowcount


class _FakeDb:
    def __init__(self, rowcount):
        self.rowcount = rowcount
        self.statement = None
        self.committed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, statement):
        self.statement = statement
        return _Result(self.rowcount)

    def commit(self):
        self.committed = True


def test_reap_stale_runs_marks_abandoned_rows_failed(monkeypatch):
    db = _FakeDb(rowcount=2)
    monkeypatch.setattr(sync_runs, "SyncSessionLocal", lambda: db)

    assert sync_runs.reap_stale_runs(timedelta(hours=6)) == 2
    assert db.committed is True

    compiled = str(db.statement)
    assert "UPDATE sync_runs" in compiled
    assert "status" in compiled


def test_reap_stale_runs_survives_db_errors(monkeypatch):
    def _boom():
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(sync_runs, "SyncSessionLocal", _boom)

    # Diagnostics must not break just because the reaper could not run.
    assert sync_runs.reap_stale_runs() == 0
