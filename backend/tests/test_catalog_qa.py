from app.services.catalog_qa import BRIEF_LAUNCH_PRODUCTS, audit_seed_catalog, load_seed_catalog


def test_seed_catalog_covers_brief_launch_list():
    audit = audit_seed_catalog(load_seed_catalog())

    assert audit["brief_launch_count"] == len(BRIEF_LAUNCH_PRODUCTS)
    assert audit["missing_launch_products"] == []


def test_seed_catalog_has_no_duplicate_names_or_mappings():
    audit = audit_seed_catalog(load_seed_catalog())

    assert audit["duplicate_display_names"] == []
    assert audit["duplicate_mappings"] == []
    assert audit["malformed_mappings"] == []
    assert audit["invalid_categories"] == []
