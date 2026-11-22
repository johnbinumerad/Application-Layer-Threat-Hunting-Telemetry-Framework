from tools.labctl.up import check_ports, extract_published_ports, run_up

GOOD = {
    "services": {
        "gateway": {"ports": [{"mode": "ingress", "host_ip": "127.0.0.1", "target": 8080, "published": "8080", "protocol": "tcp"}]},
        "target-api": {},
    }
}


def test_extracts_ports():
    assert extract_published_ports(GOOD)[0]["published"] == 8080


def test_good_config_passes():
    assert check_ports(GOOD, lambda p: True) == []


def test_non_loopback_rejected_and_named():
    cfg = {"services": {"x": {"ports": ["0.0.0.0:9200:9200"]}}}
    errs = check_ports(cfg, lambda p: True)
    assert errs and "9200" in errs[0]


def test_missing_host_ip_rejected():
    cfg = {"services": {"x": {"ports": [{"target": 80, "published": "8080"}]}}}
    assert check_ports(cfg, lambda p: True)


def test_busy_port_rejected():
    errs = check_ports(GOOD, lambda p: False)
    assert errs and "8080" in errs[0]


def test_run_up_failure_runs_down_and_nonzero():
    calls = []
    rc = run_up(lambda: GOOD, lambda a: calls.append(a) or 0, lambda p: False, stderr=open("/dev/null", "w"))
    assert rc != 0 and calls == [["docker", "compose", "down"]]


def test_run_up_success_runs_up():
    calls = []
    rc = run_up(lambda: GOOD, lambda a: calls.append(a) or 0, lambda p: True)
    assert rc == 0 and calls == [["docker", "compose", "up", "-d"]]
