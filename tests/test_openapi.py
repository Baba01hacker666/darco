import json

import yaml
from click.testing import CliRunner

from darco.cli import cli
from darco.models import (
    BodyType,
    Endpoint,
    Form,
    FormInput,
    HistoryRecord,
    NameValue,
    Request,
    Response,
    SiteMap,
)
from darco.openapi import export_openapi
from darco.workspace import Workspace


def test_export_openapi_from_sitemap():
    sitemap = SiteMap(
        target="http://api.example.com",
        endpoints=[
            Endpoint(
                url="http://api.example.com/items",
                methods=["GET"],
                params=[NameValue(name="page", value="1"), NameValue(name="limit", value="10")],
                status=200,
            )
        ],
        forms=[
            Form(
                action="http://api.example.com/login",
                method="POST",
                inputs=[
                    FormInput(name="username", default="admin"),
                    FormInput(name="password", default="pass"),
                ],
            )
        ],
    )

    spec = export_openapi(sitemap=sitemap)
    assert isinstance(spec, dict)
    assert spec["openapi"] == "3.0.3"
    assert spec["servers"][0]["url"] == "http://api.example.com"
    assert "/items" in spec["paths"]
    assert "get" in spec["paths"]["/items"]
    params = spec["paths"]["/items"]["get"]["parameters"]
    assert any(p["name"] == "page" for p in params)
    assert "/login" in spec["paths"]
    assert "post" in spec["paths"]["/login"]


def test_export_openapi_from_history():
    history = [
        HistoryRecord(
            id="0001",
            ts="2026-08-30T12:00:00Z",
            request=Request(
                method="POST",
                url="http://api.example.com/users",
                body_type=BodyType.JSON,
                body_json={"name": "Alice", "age": 30, "active": True},
            ),
            response=Response(
                status_code=201,
                reason="Created",
                headers=[NameValue(name="Content-Type", value="application/json")],
                body='{"id": 123, "name": "Alice"}',
                body_len=26,
            ),
        )
    ]

    spec = export_openapi(history=history)
    assert "/users" in spec["paths"]
    post_op = spec["paths"]["/users"]["post"]
    assert "application/json" in post_op["requestBody"]["content"]
    assert "201" in post_op["responses"]


def test_export_openapi_yaml():
    sitemap = SiteMap(
        target="http://api.example.com",
        endpoints=[Endpoint(url="http://api.example.com/ping", methods=["GET"])],
    )
    yaml_str = export_openapi(sitemap=sitemap, as_yaml=True)
    assert isinstance(yaml_str, str)
    loaded = yaml.safe_load(yaml_str)
    assert loaded["openapi"] == "3.0.3"
    assert "/ping" in loaded["paths"]


def test_cli_openapi_command(tmp_path):
    ws = Workspace.create("http://target.test", path=tmp_path / ".darco")
    sitemap = SiteMap(
        target="http://target.test",
        endpoints=[Endpoint(url="http://target.test/api/health", methods=["GET"])],
    )
    ws.save_sitemap(sitemap)

    runner = CliRunner()
    res = runner.invoke(cli, ["--workspace", str(tmp_path / ".darco"), "--json", "openapi"])
    assert res.exit_code == 0, res.output
    data = json.loads(res.stdout)
    assert data["openapi"] == "3.0.3"
    assert "/api/health" in data["paths"]
