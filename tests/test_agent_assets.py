from soc_copilot.agent.assets import load_asset_inventory, make_asset_lookup


def test_load_asset_inventory_reads_real_data_file():
    inventory = load_asset_inventory()
    assert "WKS-EU-0231" in inventory
    assert inventory["WKS-EU-0231"]["criticality"] == "high"


def test_lookup_known_host_returns_found_true_and_merges_fields():
    inventory = {"WKS-01": {"owner": "alice", "criticality": "high", "department": "IT", "asset_type": "workstation"}}
    lookup = make_asset_lookup(inventory)
    result = lookup("WKS-01")
    assert result["found"] is True
    assert result["hostname"] == "WKS-01"
    assert result["owner"] == "alice"
    assert result["criticality"] == "high"


def test_lookup_unknown_host_returns_found_false_with_a_clear_note():
    lookup = make_asset_lookup({})
    result = lookup("SOME-UNKNOWN-HOST")
    assert result["found"] is False
    assert result["hostname"] == "SOME-UNKNOWN-HOST"
    assert "note" in result
