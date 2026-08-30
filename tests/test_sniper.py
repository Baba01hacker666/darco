import json

from click.testing import CliRunner

from darco.cli import cli
from darco.models import NameValue, Request
from darco.sniper import (
    apply_payloads,
    build_attack_matrix,
    execute_sniper,
    find_positions,
    parse_payload_source,
)


def test_find_positions_and_substitute():
    req = Request(
        method="GET",
        url="http://example.com/api/users/§123§",
        params=[NameValue(name="role", value="§admin§")],
        headers=[NameValue(name="X-Custom", value="§header_val§")],
    )

    positions = find_positions(req, marker="§")
    assert len(positions) == 3
    assert positions[0].loc_type == "url"
    assert positions[1].loc_type == "param"
    assert positions[2].loc_type == "header"

    # Substitute payload for position 0 (URL)
    mutated = apply_payloads(req, positions, {0: "999"}, marker="§")
    assert mutated.url == "http://example.com/api/users/999"
    assert mutated.params[0].value == "admin"
    assert mutated.headers[0].value == "header_val"


def test_attack_matrix_sniper():
    # 2 positions, payload list ["a", "b"] -> 4 requests (2 for pos0, 2 for pos1)
    matrix = build_attack_matrix("sniper", 2, [["a", "b"]])
    assert len(matrix) == 4
    assert matrix[0] == {0: "a"}
    assert matrix[1] == {0: "b"}
    assert matrix[2] == {1: "a"}
    assert matrix[3] == {1: "b"}


def test_attack_matrix_battering_ram():
    # 2 positions, payload list ["a", "b"] -> 2 requests ({0: 'a', 1: 'a'}, {0: 'b', 1: 'b'})
    matrix = build_attack_matrix("battering_ram", 2, [["a", "b"]])
    assert len(matrix) == 2
    assert matrix[0] == {0: "a", 1: "a"}
    assert matrix[1] == {0: "b", 1: "b"}


def test_attack_matrix_pitchfork():
    # 2 positions, payload lists [["u1", "u2"], ["p1", "p2"]] -> 2 requests in lockstep
    matrix = build_attack_matrix("pitchfork", 2, [["u1", "u2"], ["p1", "p2"]])
    assert len(matrix) == 2
    assert matrix[0] == {0: "u1", 1: "p1"}
    assert matrix[1] == {0: "u2", 1: "p2"}


def test_attack_matrix_cluster_bomb():
    # 2 positions, payload lists [["u1", "u2"], ["p1", "p2"]] -> 4 requests (Cartesian product)
    matrix = build_attack_matrix("cluster_bomb", 2, [["u1", "u2"], ["p1", "p2"]])
    assert len(matrix) == 4
    assert matrix[0] == {0: "u1", 1: "p1"}
    assert matrix[1] == {0: "u1", 1: "p2"}
    assert matrix[2] == {0: "u2", 1: "p1"}
    assert matrix[3] == {0: "u2", 1: "p2"}


def test_parse_payload_sources(tmp_path):
    # Comma list
    assert parse_payload_source("foo,bar,baz") == ["foo", "bar", "baz"]

    # Number range
    assert parse_payload_source("1-5") == ["1", "2", "3", "4", "5"]
    assert parse_payload_source("01-05:2") == ["01", "03", "05"]

    # File
    f = tmp_path / "words.txt"
    f.write_text("root\nadmin\nguest\n")
    assert parse_payload_source(str(f)) == ["root", "admin", "guest"]


def test_execute_sniper_against_mock(app):
    req = Request(
        method="GET",
        url=f"{app}/debug",
        params=[NameValue(name="enabled", value="§default§")],
    )

    report = execute_sniper(
        req,
        mode="sniper",
        payload_lists=[["alice", "bob", "admin"]],
        match_regex="admin",
    )

    assert report.total_positions == 1
    assert report.total_requests == 3
    assert len(report.results) == 3
    assert any("regex_match" in r.matches for r in report.results)


def test_cli_sniper_command(app):
    runner = CliRunner()
    res = runner.invoke(
        cli,
        [
            "--json",
            "sniper",
            f"{app}/echo?q=§test§",
            "--mode",
            "sniper",
            "--payload",
            "val1,val2",
        ],
    )
    assert res.exit_code == 0, res.output
    data = json.loads(res.stdout)
    assert data["mode"] == "sniper"
    assert data["total_requests"] == 2
    assert len(data["results"]) == 2
