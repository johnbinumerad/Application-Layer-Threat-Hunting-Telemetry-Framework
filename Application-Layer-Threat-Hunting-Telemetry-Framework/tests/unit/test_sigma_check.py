import copy

from labcommon.sigma_check import check_directory, check_document, known_fields

FIELDS = known_fields()
GOOD = {
    "title": "t", "id": "1b6d3f8a-4e27-4c90-a5d1-7f2e9b0c8d21", "status": "experimental",
    "description": "d", "logsource": {"category": "application"},
    "detection": {"selection": {"event.dataset|contains": "x"}, "condition": "selection"},
    "falsepositives": ["fp"], "level": "high", "tags": ["attack.t1190"],
}


def test_repo_rules_are_valid():
    result = check_directory("detections/sigma")
    assert result.ok, [str(r) for r in result.rejected]
    assert len(result.valid_files) >= 3


def test_good_document_accepted():
    assert check_document(GOOD, FIELDS) == []


def test_each_defect_rejected():
    for key in ("title", "id", "status", "description", "logsource", "detection",
                "falsepositives", "level", "tags"):
        bad = copy.deepcopy(GOOD)
        del bad[key]
        assert check_document(bad, FIELDS), key
    for mutate in (
        lambda d: d.update(id="nope"),
        lambda d: d.update(level="severe"),
        lambda d: d.update(tags=["foo.bar"]),
        lambda d: d["detection"].pop("condition"),
        lambda d: d["detection"]["selection"].update({"not.a.field": 1}),
    ):
        bad = copy.deepcopy(GOOD)
        mutate(bad)
        assert check_document(bad, FIELDS)
