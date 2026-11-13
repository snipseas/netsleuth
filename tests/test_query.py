import sqlite3

import pytest

from netsleuth.storage.query import FilterError, parse_filter


def test_basic_terms():
    sql, params = parse_filter("ip:10.0.0.5 port:443 proto:tcp flag:syn len>1000", "packets")
    assert params == ["10.0.0.5", "10.0.0.5", 443, 443, "TCP", 2, 1000.0]
    assert sql.count("?") == len(params)
    sql, params = parse_filter("-proto:arp 10.0.0.1 hello", "packets")
    assert "IS NOT TRUE" in sql and params[0] == "ARP" and params[-1] == "%hello%"
    assert parse_filter("", "flows") == ("", [])
    sql, params = parse_filter('state:s0 bytes>=5000 name:example fd00::1', "flows")
    assert params == ["S0", 5000.0, "%example%", "%example%", "fd00::1", "fd00::1"]


@pytest.mark.parametrize("bad", ["nosuchkey:1", "port:abc", "flag:zzz", "port>5", 'info:"unbalanced',
                                 "len>nan", "x " * 40, "a" * 600])
def test_invalid_filters_raise(bad):
    with pytest.raises(FilterError):
        parse_filter(bad, "packets")


@pytest.mark.parametrize("attack", [
    "'; DROP TABLE packets; --", "1 OR 1=1", "src:' OR '1'='1", "info:%' UNION SELECT * FROM meta --",
    'proto:tcp"; DELETE FROM flows; --', "ip:1.1.1.1) OR (1=1", "\\", "%", "_"])
def test_user_input_never_reaches_sql_text(attack):
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE packets (no, ts, len, src, dst, sport, dport, proto, net, flags, flow_id, info)")
    db.execute("CREATE TABLE flows (id, app)")
    db.execute("INSERT INTO packets VALUES (1, 0, 60, '10.0.0.1', '10.0.0.2', 1, 2, 'TCP', 'IPv4', 2, 1, 'x')")
    try:
        sql, params = parse_filter(attack, "packets")
    except FilterError:
        return
    for fragment in ("DROP", "UNION", "DELETE", "1=1"):
        assert fragment not in sql
    rows = db.execute(f"SELECT * FROM packets p WHERE {sql}", params).fetchall()
    assert rows == []                      # nothing matches, and nothing was injected
    assert db.execute("SELECT COUNT(*) FROM packets").fetchone()[0] == 1
