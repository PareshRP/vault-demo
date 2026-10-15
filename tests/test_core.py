import pytest
from vault_portal.core import InstructionError, apply_operations, parse_instruction, parse_key_reference

def test_parse_set_and_nested():
    parsed = parse_instruction("SECRET: team/app\nSET name = demo\nSET_NESTED config : region = ap-south-1")
    assert parsed["secret_path"] == "team/app"
    assert [op["type"] for op in parsed["operations"]] == ["set", "set_nested"]

def test_values_keep_equals_and_hash():
    parsed = parse_instruction("SECRET: demo\nSET url = https://example.invalid?a=b#fragment")
    assert parsed["operations"][0]["value"] == "https://example.invalid?a=b#fragment"

def test_empty_values_allowed():
    parsed = parse_instruction("SECRET: demo\nSET empty = ")
    assert parsed["operations"][0]["value"] == ""

def test_comments_and_blank_lines():
    parsed = parse_instruction("\n# comment\nSECRET: demo\n\n# another comment\nSET x = y\n")
    assert len(parsed["operations"]) == 1

@pytest.mark.parametrize("text", [
    "SET x = y\nSECRET: demo",
    "SECRET: ../escape\nSET x = y",
    "SECRET: /absolute\nSET x = y",
    "SECRET: a//b\nSET x = y",
    "SECRET: demo\nDELETE x",
    "SECRET: demo\nSET = missing-key",
])
def test_rejects_malformed_and_unsafe(text):
    with pytest.raises(InstructionError):
        parse_instruction(text)

def test_update_preserves_unrelated_keys_and_adds_key():
    result = apply_operations({"existing": "old", "keep": "untouched"}, [
        {"type": "set", "key": "existing", "value": "new"},
        {"type": "set", "key": "added", "value": "yes"},
    ])
    assert result == {"existing": "new", "keep": "untouched", "added": "yes"}

def test_nested_update_preserves_other_lines():
    current = {"config": "token=old\nregion=west\n# keep comment"}
    result = apply_operations(current, [{"type": "set_nested", "key": "config", "sub_key": "token", "value": "new"}])
    assert result["config"] == "token=new\nregion=west\n# keep comment"

def test_nested_missing_subkey_appended_and_missing_outer_created():
    result = apply_operations({}, [{"type": "set_nested", "key": "config", "sub_key": "region", "value": "east"}])
    assert result["config"] == "region=east"
    result2 = apply_operations({"config": "token=old"}, [{"type": "set_nested", "key": "config", "sub_key": "region", "value": "east"}])
    assert result2["config"] == "token=old\nregion=east"

def test_nested_rejects_non_string_outer_key():
    with pytest.raises(InstructionError):
        apply_operations({"config": {"token": "old"}}, [{"type": "set_nested", "key": "config", "sub_key": "token", "value": "new"}])

def test_unchanged_is_detectable():
    instruction = parse_instruction("SECRET: demo\nSET x = same")
    before = {"x": "same"}
    assert apply_operations(before, instruction["operations"]) == before

def test_key_reference_format_is_preserved_for_resolution():
    parsed = parse_instruction("SECRET: team/service-config\nSET gcp_id = Key: <shared/gcp.gcp_id>")
    assert parsed["operations"][0]["value"] == "Key: <shared/gcp.gcp_id>"
    assert parse_key_reference(parsed["operations"][0]["value"]) == ("shared/gcp", "gcp_id")

def test_nested_key_reference_format():
    parsed = parse_instruction("SECRET: team/service-config\nSET_NESTED config : region = Key: <shared/config.region>")
    assert parse_key_reference(parsed["operations"][0]["value"]) == ("shared/config", "region")

def test_malformed_key_reference_rejected():
    with pytest.raises(InstructionError):
        parse_instruction("SECRET: target\nSET copied = Key: <../unsafe.key>")
    with pytest.raises(InstructionError):
        parse_instruction("SECRET: target\nSET copied = Key: missing-angle-brackets")
