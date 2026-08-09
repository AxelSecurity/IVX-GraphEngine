"""Tests for DOM normalisation and hashing."""

from __future__ import annotations

from graph_engine.dom_hash import normalise_and_hash


# ---------------------------------------------------------------------------
# Critical: same logical DOM → same hash (dedup invariant)
# ---------------------------------------------------------------------------

SAME_BASE_1 = """<html><head><script nonce="abc123">var t=1740000000;</script></head><body><div id="main" data-timestamp="1740000000">Welcome</div></body></html>"""

SAME_BASE_2 = """<html><head><script nonce="xyz789">var t=1741111111;</script></head><body><div id="main" data-timestamp="1741111111">Welcome</div></body></html>"""


def test_different_nonce_and_timestamp_produce_same_hash():
    """Two pages identical except for nonce + timestamps MUST hash the same."""
    h1 = normalise_and_hash(SAME_BASE_1)
    h2 = normalise_and_hash(SAME_BASE_2)
    assert h1 == h2, f"Expected same hash but got {h1[:16]}... vs {h2[:16]}..."


def test_different_visible_content_produce_different_hash():
    """Two pages with different user-visible text MUST hash differently."""
    html_a = "<html><body><h1>Login to Microsoft</h1></body></html>"
    html_b = "<html><body><h1>Login to Google</h1></body></html>"
    assert normalise_and_hash(html_a) != normalise_and_hash(html_b)


# ---------------------------------------------------------------------------
# Additional coverage
# ---------------------------------------------------------------------------


def test_attribute_order_does_not_matter():
    """Attributes in different order → same hash."""
    a = '<div class="foo" id="bar" data-x="1">text</div>'
    b = '<div data-x="1" id="bar" class="foo">text</div>'
    assert normalise_and_hash(a) == normalise_and_hash(b)


def test_csrf_token_attribute_stripped():
    """CSRF token attribute is stripped → same hash."""
    a = '<form action="/login"><input name="csrf-token" value="abc"></form>'
    b = '<form action="/login"><input name="csrf-token" value="def"></form>'
    assert normalise_and_hash(a) == normalise_and_hash(b)


def test_uuid_attribute_value_stripped():
    """Attribute whose value is a UUID is stripped → same hash."""
    a = '<div data-uuid="550e8400-e29b-41d4-a716-446655440000">X</div>'
    b = '<div data-uuid="6ba7b810-9dad-11d1-80b4-00c04fd430c8">X</div>'
    assert normalise_and_hash(a) == normalise_and_hash(b)


def test_nested_elements_normalised():
    """Normalisation descends into children."""
    a = '<div><span nonce="x" class="c1">A</span><span nonce="y" class="c1">B</span></div>'
    b = '<div><span nonce="z" class="c1">A</span><span nonce="w" class="c1">B</span></div>'
    assert normalise_and_hash(a) == normalise_and_hash(b)


def test_empty_input():
    """Empty string should not crash."""
    result = normalise_and_hash("")
    assert isinstance(result, str)
    assert len(result) == 64  # SHA-256 hex digest length


def test_bare_text_no_tags():
    """Plain text without HTML tags should not crash."""
    result = normalise_and_hash("just some text")
    assert len(result) == 64


def test_id_attribute_preserved():
    """'id' attribute values are kept even when numeric-looking."""
    a = '<div id="1234567890">content</div>'
    b = '<div id="1234567890">content</div>'
    h = normalise_and_hash(a)
    assert normalise_and_hash(b) == h
    # And a different id produces a different hash.
    c = '<div id="0987654321">content</div>'
    assert normalise_and_hash(c) != h


def test_sha256_hash_format():
    """Return value is a 64-char lowercase hex string."""
    digest = normalise_and_hash("<p>hello</p>")
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)
