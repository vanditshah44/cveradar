from types import SimpleNamespace
from uuid import uuid4

from sqlalchemy.dialects import postgresql

from app.models.cve import CveAffectedProduct
from app.models.match import UserCveMatch
from app.models.stack_item import StackItem
from app.tasks.matcher import match_cve_against_stacks


class ScalarRows:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return self

    def all(self):
        return self.rows


class FakeMatcherDb:
    def __init__(self, *, cves, affected_by_cve, stack_items):
        self.cves = cves
        self.affected_by_cve = affected_by_cve
        self.stack_items = stack_items
        self.inserted = []
        self.deletes = []

    def get(self, model, key):
        return self.cves.get(key)

    def execute(self, statement):
        table = getattr(statement, "table", None)
        if table is not None and table.name == UserCveMatch.__tablename__:
            compiled = statement.compile(dialect=postgresql.dialect())
            sql = str(compiled)
            if sql.lstrip().startswith("INSERT"):
                self.inserted.append(compiled.params)
            elif sql.lstrip().startswith("DELETE"):
                self.deletes.append(sql)
            return None

        entity = statement.column_descriptions[0]["entity"]
        compiled = statement.compile(dialect=postgresql.dialect())
        params = list(compiled.params.values())

        if entity is CveAffectedProduct:
            return ScalarRows(self.affected_by_cve.get(params[0], []))

        if entity is StackItem:
            vendor, product = params[:2]
            items = [
                item
                for item in self.stack_items
                if item.vendor == vendor and item.cpe_product == product
            ]
            return ScalarRows(items)

        raise AssertionError(f"Unexpected statement: {statement}")


def test_match_cve_against_stacks_runs_insert_and_reconcile_flow():
    cve_id = "CVE-2026-4242"
    cve = SimpleNamespace(cve_id=cve_id, cvss_score=9.8, epss_score=0.8, kev_flag=True)
    requirement = SimpleNamespace(
        id=uuid4(),
        cve_id=cve_id,
        vendor="nginx",
        product="nginx",
        version_start="1.20.0",
        version_start_including=True,
        version_end="1.24.3",
        version_end_including=False,
        single_version=None,
        condition_group="group-1",
        is_vulnerable_match=True,
    )
    matching_item = SimpleNamespace(
        id=uuid4(),
        user_id=uuid4(),
        vendor="nginx",
        cpe_product="nginx",
        version="1.24.0",
    )
    non_matching_item = SimpleNamespace(
        id=uuid4(),
        user_id=uuid4(),
        vendor="nginx",
        cpe_product="nginx",
        version="1.25.0",
    )

    db = FakeMatcherDb(
        cves={cve_id: cve},
        affected_by_cve={cve_id: [requirement]},
        stack_items=[matching_item, non_matching_item],
    )

    count = match_cve_against_stacks(db, cve_id)

    assert count == 1
    assert len(db.inserted) == 1
    assert any("DELETE FROM user_cve_matches" in sql for sql in db.deletes)
