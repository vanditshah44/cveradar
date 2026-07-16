from uuid import uuid4

from sqlalchemy.dialects import postgresql

from app.tasks.matcher import _reconcile_matches_for_cve


class RecordingDb:
    def __init__(self):
        self.statements = []

    def execute(self, statement):
        self.statements.append(statement)


def _compile_sql(statement) -> str:
    return str(statement.compile(dialect=postgresql.dialect()))


def test_reconcile_matches_for_cve_deletes_non_matching_stack_items_only():
    db = RecordingDb()

    _reconcile_matches_for_cve(db, "CVE-2026-0001", {uuid4(), uuid4()})

    sql = _compile_sql(db.statements[0])

    assert "DELETE FROM user_cve_matches" in sql
    assert "cve_id" in sql
    assert "NOT IN" in sql


def test_reconcile_matches_for_cve_deletes_all_matches_when_no_stack_items_remain():
    db = RecordingDb()

    _reconcile_matches_for_cve(db, "CVE-2026-0002", set())

    sql = _compile_sql(db.statements[0])

    assert "DELETE FROM user_cve_matches" in sql
    assert "cve_id" in sql
    assert "NOT IN" not in sql
