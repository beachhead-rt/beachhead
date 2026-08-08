from __future__ import annotations

from collections.abc import Callable

from beachhead.core.auth.audience import Audience, classify_audience


def test_graph_url_audience(make_jwt: Callable[..., str]) -> None:
    assert classify_audience(make_jwt("https://graph.microsoft.com")) == Audience.GRAPH


def test_graph_appid_audience(make_jwt: Callable[..., str]) -> None:
    tok = make_jwt("00000003-0000-0000-c000-000000000000")
    assert classify_audience(tok) == Audience.GRAPH


def test_arm_url_audience(make_jwt: Callable[..., str]) -> None:
    assert classify_audience(make_jwt("https://management.azure.com")) == Audience.ARM


def test_arm_url_trailing_slash(make_jwt: Callable[..., str]) -> None:
    assert classify_audience(make_jwt("https://management.azure.com/")) == Audience.ARM


def test_management_core_windows_net(make_jwt: Callable[..., str]) -> None:
    tok = make_jwt("https://management.core.windows.net/")
    assert classify_audience(tok) == Audience.ARM


def test_unknown_audience_is_none(make_jwt: Callable[..., str]) -> None:
    assert classify_audience(make_jwt("https://vault.azure.net")) is None


def test_missing_aud_is_none(make_jwt: Callable[..., str]) -> None:
    assert classify_audience(make_jwt(None)) is None


def test_case_insensitive(make_jwt: Callable[..., str]) -> None:
    assert classify_audience(make_jwt("HTTPS://GRAPH.MICROSOFT.COM")) == Audience.GRAPH


def test_non_jwt_string_is_none() -> None:
    assert classify_audience("not-a-jwt") is None


def test_two_segment_string_is_none() -> None:
    assert classify_audience("a.b") is None


def test_bad_base64_payload_is_none() -> None:
    assert classify_audience("aaa.!!!notbase64!!!.sig") is None


def test_never_raises_on_garbage() -> None:
    for junk in ["", ".", "..", "a.b.c.d"]:
        assert classify_audience(junk) is None
