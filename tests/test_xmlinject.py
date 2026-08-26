"""Unit tests for darco.xmlinject (XML body parsing + entity encoding)."""

import xml.etree.ElementTree as ET

from darco.models import BodyType, NameValue, Request
from darco.xmlinject import (
    content_type_of,
    looks_like_xml,
    parse_xml_params,
    replace_element_text,
    truncate_after_element_text,
    xml_entity_encode,
)


def _xml_request(body: str) -> Request:
    return Request(
        method="POST",
        url="http://app.test/stock",
        headers=[NameValue(name="Content-Type", value="application/xml")],
        body_type=BodyType.RAW,
        body_raw=body,
    )


def test_xml_entity_encode_roundtrip():
    payload = "1 UNION SELECT username || '~' || password FROM users"
    enc = xml_entity_encode(payload)
    assert "&#x55;" in enc  # U
    assert "&#x4E;" in enc  # N
    assert "UNION" not in enc  # a WAF scanning raw bytes sees no keyword
    assert "SELECT" not in enc
    assert ET.fromstring(f"<storeId>{enc}</storeId>").text == payload


def test_xml_entity_encode_keeps_whitespace_literal():
    enc = xml_entity_encode("1 OR 1=1")
    assert enc == "&#x31; &#x4F;&#x52; &#x31;&#x3D;&#x31;"
    assert " OR " not in enc
    assert ET.fromstring(f"<x>{enc}</x>").text == "1 OR 1=1"


def test_parse_xml_params_and_replace_body():
    body = "<root><storeId>1</storeId><name>acme</name></root>"
    params = parse_xml_params(body)
    assert [(p.name, p.value) for p in params] == [
        ("storeId", "1"),
        ("name", "acme"),
    ]

    replaced = replace_element_text(body, "storeId", "1", "&#x31;")
    assert replaced == "<root><storeId>&#x31;</storeId><name>acme</name></root>"

    assert truncate_after_element_text(body, "storeId", "1") == "<root><storeId>1"

    # old_value=None replaces the first occurrence regardless of text
    assert replace_element_text(body, "name", None, "x") == (
        "<root><storeId>1</storeId><name>x</name></root>"
    )


def test_parse_xml_params_skips_non_leaf_and_empty():
    body = "<root>ignored<item code='7'>5</item><empty></empty></root>"
    params = parse_xml_params(body)
    assert [(p.name, p.value) for p in params] == [("item", "5")]


def test_parse_xml_params_namespaced():
    body = '<soap:root xmlns:soap="urn:x"><soap:storeId>9</soap:storeId></soap:root>'
    params = parse_xml_params(body)
    assert [(p.name, p.value) for p in params] == [("storeId", "9")]


def test_looks_like_xml_by_content_type_and_body():
    assert looks_like_xml(_xml_request("<storeId>1</storeId>"))
    assert looks_like_xml(
        Request(
            method="POST",
            url="http://app.test/x",
            headers=[],
            body_type=BodyType.RAW,
            body_raw="<?xml version='1.0'?><a>1</a>",
        )
    )
    # plain text body without xml content-type is not treated as XML
    assert not looks_like_xml(
        Request(
            method="POST",
            url="http://app.test/x",
            headers=[],
            body_type=BodyType.RAW,
            body_raw="storeId=1",
        )
    )


def test_content_type_of():
    req = _xml_request("<storeId>1</storeId>")
    assert content_type_of(req) == "application/xml"
