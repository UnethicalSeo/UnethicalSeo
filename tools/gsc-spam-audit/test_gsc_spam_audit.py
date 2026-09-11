"""Tests for the audit logic, run against a fake Search Console service.

    python -m pytest test_gsc_spam_audit.py      # or just: python test_gsc_spam_audit.py
"""

from __future__ import annotations

import datetime as dt
import json
import sys
import tempfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))

import gsc_spam_audit as A


# ------------------------------------------------------------------- windows

def test_windows_are_equal_whole_weeks_after_the_rollout():
    pre, post = A.resolve_windows(dt.date(2026, 8, 18), dt.date(2026, 8, 21),
                                  dt.date(2026, 9, 11), lag_days=3, max_window=28)
    assert pre == (dt.date(2026, 8, 4), dt.date(2026, 8, 17))
    assert post == (dt.date(2026, 8, 26), dt.date(2026, 9, 8))
    assert (pre[1] - pre[0]).days == (post[1] - post[0]).days
    assert ((pre[1] - pre[0]).days + 1) % 7 == 0
    assert post[0] > dt.date(2026, 8, 21)


def test_settled_update_caps_at_max_window():
    _, post = A.resolve_windows(dt.date(2026, 3, 24), dt.date(2026, 3, 25),
                                dt.date(2026, 9, 11), lag_days=3, max_window=28)
    assert (post[1] - post[0]).days + 1 == 28


def test_refuses_to_compare_before_a_week_of_final_data():
    try:
        A.resolve_windows(dt.date(2026, 9, 1), dt.date(2026, 9, 5),
                          dt.date(2026, 9, 8), lag_days=3, max_window=28)
    except SystemExit:
        return
    raise AssertionError("should have refused a sub-week window")


# -------------------------------------------------------------------- totals

def test_position_and_ctr_are_impression_weighted():
    rows = [{"clicks": 10, "impressions": 100, "position": 5.0},
            {"clicks": 0, "impressions": 900, "position": 50.0}]
    totals = A.totals_from_rows(rows)
    assert totals.clicks == 10 and totals.impressions == 1000
    assert abs(totals.position - 45.5) < 1e-9   # not the naive (5 + 50) / 2
    assert abs(totals.ctr - 0.01) < 1e-9


def test_empty_property_does_not_divide_by_zero():
    totals = A.totals_from_rows([])
    assert totals.position == 0.0 and totals.ctr == 0.0
    assert A.pct_delta(0, 0) is None
    assert A.pct_delta(0, 5) == float("inf")
    assert A.pct_delta(100, 50) == -50.0


# ------------------------------------------------------------ classification

def _verdict(pre_clicks, post_clicks, pre_impr, post_impr, position_delta=1.0):
    return A.classify(
        A.Totals(clicks=pre_clicks, impressions=pre_impr),
        A.Totals(clicks=post_clicks, impressions=post_impr),
        A.pct_delta(pre_clicks, post_clicks),
        A.pct_delta(pre_impr, post_impr),
        position_delta, hit_threshold=25.0, min_clicks=30, min_impressions=500,
    )


def test_verdicts():
    assert _verdict(1000, 200, 50000, 20000) == "SEVERE HIT"
    assert _verdict(1000, 700, 50000, 45000) == "HIT"
    # Clicks falling while impressions hold is a SERP-layout story, not a demotion.
    assert _verdict(1000, 600, 50000, 50000) == "CLICKS DOWN / IMPRESSIONS HELD"
    assert _verdict(4, 1, 60, 30) == "LOW VOLUME"
    # Thin clicks but real impressions still carry signal.
    assert _verdict(20, 13, 4000, 3200) == "HIT"
    assert _verdict(1000, 980, 50000, 49000) == "STABLE"
    assert _verdict(1000, 1400, 50000, 60000) == "UP"


# ------------------------------------------------------------- end to end

SITES = ["sc-domain:penalised.com", "https://stable.example/", "sc-domain:tiny.net"]


class _Req:
    def __init__(self, payload): self.payload = payload
    def execute(self): return self.payload


class _FakeSearchAnalytics:
    def query(self, siteUrl, body):
        start = dt.date.fromisoformat(body["startDate"])
        end = dt.date.fromisoformat(body["endDate"])
        after = start > dt.date(2026, 8, 21)
        dims = body["dimensions"]
        if siteUrl == "sc-domain:penalised.com":
            clicks, impressions = (12, 400) if after else (120, 4000)
        elif siteUrl == "sc-domain:tiny.net":
            clicks, impressions = (0, 8) if after else (1, 15)
        else:
            clicks, impressions = 90, 3000
        position = 24.0 if after else 8.0
        if dims == ["date"]:
            days = (end - start).days + 1
            return _Req({"rows": [
                {"keys": [(start + dt.timedelta(days=i)).isoformat()],
                 "clicks": clicks, "impressions": impressions, "position": position}
                for i in range(days)]})
        rows = 3 if after else 6   # three keys vanish entirely after the update
        return _Req({"rows": [
            {"keys": [f"{dims[0]}-{i}"], "clicks": clicks * (6 - i),
             "impressions": impressions * (6 - i), "position": position}
            for i in range(rows)]})


class _FakeSites:
    def list(self):
        entries = [{"siteUrl": s, "permissionLevel": "siteOwner"} for s in SITES]
        entries.append({"siteUrl": "https://nope/", "permissionLevel": "siteUnverifiedUser"})
        return _Req({"siteEntry": entries})


class _FakeService:
    def sites(self): return _FakeSites()
    def searchanalytics(self): return _FakeSearchAnalytics()


def test_end_to_end_report():
    with tempfile.TemporaryDirectory() as out:
        argv = ["gsc_spam_audit.py", "--today", "2026-09-11", "--out-dir", out]
        with mock.patch.object(A, "build", lambda *a, **k: _FakeService()), \
             mock.patch.object(A, "load_credentials", lambda *a, **k: None), \
             mock.patch.object(sys, "argv", argv):
            A.main()

        report = json.loads(Path(out, "gsc-audit-2026-09-11.json").read_text())

    by_site = {r["site_url"]: r for r in report["results"]}
    assert by_site["sc-domain:penalised.com"]["verdict"] == "SEVERE HIT"
    assert by_site["https://stable.example/"]["verdict"] == "STABLE"
    assert by_site["sc-domain:tiny.net"]["verdict"] == "LOW VOLUME"
    assert "https://nope/" not in by_site, "unverified property must be skipped"

    # tiny.net fell 100% against penalised.com's 90%; the real loss still leads.
    assert report["results"][0]["site_url"] == "sc-domain:penalised.com"
    assert any(p["dropped_out"] for p in by_site["sc-domain:penalised.com"]["losers_pages"])
    assert by_site["https://stable.example/"]["losers_pages"] == [], "stable sites are not drilled"


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            passed += 1
            print(f"  ok  {name}")
    print(f"\n{passed} tests passed")
