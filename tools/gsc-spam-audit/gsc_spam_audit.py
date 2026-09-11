"""Find which Search Console properties lost traffic to a Google update.

Compares two equal-length windows around the update — the weeks before it
started, and the days since it finished — for every property the authorized
account can read, then drills into the worst hits to show which pages and
queries bled.

    python gsc_spam_audit.py                        # August 2026 spam update
    python gsc_spam_audit.py --update-start 2026-03-24 --update-end 2026-03-25
    python gsc_spam_audit.py --site sc-domain:example.com --drilldown-all

Caveat worth knowing before you read the output: the API exposes performance
data only. Manual actions and security issues are not in any API — if a
property looks executed rather than merely demoted, open it in the Search
Console UI and check Security & Manual Actions by hand.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import random
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from gsc_auth import load_credentials

# Rollout window of the most recent spam update at time of writing.
DEFAULT_UPDATE_START = "2026-08-18"
DEFAULT_UPDATE_END = "2026-08-21"

# Search Console finalizes data ~2-3 days back; anything fresher undercounts.
DEFAULT_LAG_DAYS = 3
DEFAULT_MAX_WINDOW = 28
RETRYABLE = {429, 500, 502, 503, 504}

# Report order. Severity first, so a 14-clicks-to-0 hobby site never pushes a
# property that shed 1,500 real clicks off the top of the table.
VERDICT_ORDER = {
    "SEVERE HIT": 0,
    "HIT": 1,
    "VISIBILITY DOWN": 2,
    "CLICKS DOWN / IMPRESSIONS HELD": 3,
    "STABLE": 4,
    "UP": 5,
    "LOW VOLUME": 6,
    "NO DATA": 7,
    "ERROR": 8,
}


@dataclass
class Totals:
    clicks: int = 0
    impressions: int = 0
    ctr: float = 0.0
    position: float = 0.0
    days: int = 0


@dataclass
class SiteResult:
    site_url: str
    permission: str
    pre: Totals
    post: Totals
    clicks_delta_pct: float | None
    impressions_delta_pct: float | None
    position_delta: float | None
    verdict: str
    losers_pages: list[dict] = field(default_factory=list)
    losers_queries: list[dict] = field(default_factory=list)
    error: str | None = None


# --------------------------------------------------------------------------- API

def _execute(request, attempts: int = 5):
    """Run an API request, backing off on the transient status codes."""
    for attempt in range(attempts):
        try:
            return request.execute()
        except HttpError as exc:
            status = getattr(exc.resp, "status", None)
            if status not in RETRYABLE or attempt == attempts - 1:
                raise
            delay = (2**attempt) + random.uniform(0, 1)
            print(f"    … {status}, retrying in {delay:.1f}s", file=sys.stderr)
            time.sleep(delay)
    raise RuntimeError("unreachable")


def list_sites(service) -> list[tuple[str, str]]:
    entries = _execute(service.sites().list()).get("siteEntry", [])
    # siteUnverifiedUser can't query performance data at all; skip the noise.
    return [
        (e["siteUrl"], e.get("permissionLevel", "unknown"))
        for e in entries
        if e.get("permissionLevel") != "siteUnverifiedUser"
    ]


def query_rows(service, site_url: str, start: dt.date, end: dt.date,
               dimensions: list[str], search_type: str, row_limit: int = 25000) -> list[dict]:
    """Page through searchanalytics.query until the API stops returning rows."""
    rows: list[dict] = []
    start_row = 0
    while True:
        body = {
            "startDate": start.isoformat(),
            "endDate": end.isoformat(),
            "dimensions": dimensions,
            "rowLimit": row_limit,
            "startRow": start_row,
            "dataState": "final",
            "type": search_type,
        }
        response = _execute(service.searchanalytics().query(siteUrl=site_url, body=body))
        batch = response.get("rows", [])
        rows.extend(batch)
        if len(batch) < row_limit:
            return rows
        start_row += row_limit


def totals_from_rows(rows: list[dict]) -> Totals:
    clicks = sum(int(r.get("clicks", 0)) for r in rows)
    impressions = sum(int(r.get("impressions", 0)) for r in rows)
    # CTR and position must be re-weighted; averaging the per-row values lies.
    weighted_position = sum(r.get("position", 0.0) * r.get("impressions", 0) for r in rows)
    return Totals(
        clicks=clicks,
        impressions=impressions,
        ctr=(clicks / impressions) if impressions else 0.0,
        position=(weighted_position / impressions) if impressions else 0.0,
        days=len(rows),
    )


# ----------------------------------------------------------------------- windows

def resolve_windows(update_start: dt.date, update_end: dt.date, today: dt.date,
                    lag_days: int, max_window: int) -> tuple[tuple[dt.date, dt.date], tuple[dt.date, dt.date]]:
    """Pick equal-length pre/post windows, snapped to whole weeks.

    Whole weeks matter: search traffic is strongly weekday-shaped, so a 10-day
    window against another 10-day window can invent a drop that is really just
    two extra Sundays.
    """
    post_end = today - dt.timedelta(days=lag_days)
    post_start_earliest = update_end + dt.timedelta(days=1)
    available = (post_end - post_start_earliest).days + 1
    if available < 7:
        raise SystemExit(
            f"Only {available} finalized day(s) since the update ended "
            f"({update_end}). Wait until at least 7 are available."
        )

    window = min(max_window, available)
    window -= window % 7  # snap down to whole weeks
    window = max(window, 7)

    post = (post_end - dt.timedelta(days=window - 1), post_end)
    pre_end = update_start - dt.timedelta(days=1)
    pre = (pre_end - dt.timedelta(days=window - 1), pre_end)
    return pre, post


def pct_delta(before: float, after: float) -> float | None:
    if before == 0:
        return None if after == 0 else float("inf")
    return (after - before) / before * 100.0


def classify(pre: Totals, post: Totals, clicks_delta: float | None,
             impressions_delta: float | None, position_delta: float | None,
             hit_threshold: float, min_clicks: int, min_impressions: int) -> str:
    """Label the shape of the change, not just its size.

    A spam-update demotion shows up as impressions falling with average
    position worsening: the pages are simply being shown less. Clicks falling
    while impressions hold is a different animal (SERP layout, AI Overviews,
    seasonality) and should not be filed under the same cause.
    """
    # Dismiss a property as noise only when both signals are thin. A site with
    # few clicks but plenty of impressions still moves readably.
    if pre.clicks < min_clicks and pre.impressions < min_impressions:
        return "LOW VOLUME"
    if clicks_delta is None:
        return "NO DATA"
    if clicks_delta <= -hit_threshold and (impressions_delta or 0) < 0:
        severe = clicks_delta <= -60 and (impressions_delta or 0) <= -40
        return "SEVERE HIT" if severe else "HIT"
    if clicks_delta <= -hit_threshold:
        return "CLICKS DOWN / IMPRESSIONS HELD"
    if (impressions_delta or 0) <= -hit_threshold and (position_delta or 0) > 0.5:
        return "VISIBILITY DOWN"
    if clicks_delta >= hit_threshold:
        return "UP"
    return "STABLE"


# --------------------------------------------------------------------- drilldown

def losers(service, site_url: str, dimension: str, pre: tuple[dt.date, dt.date],
           post: tuple[dt.date, dt.date], search_type: str, top: int) -> list[dict]:
    """Rows that lost the most clicks between the two windows."""
    def by_key(window):
        rows = query_rows(service, site_url, window[0], window[1], [dimension], search_type)
        return {r["keys"][0]: r for r in rows}

    before, after = by_key(pre), by_key(post)
    out = []
    for key, row in before.items():
        pre_clicks = int(row.get("clicks", 0))
        pre_impr = int(row.get("impressions", 0))
        post_row = after.get(key, {})
        post_clicks = int(post_row.get("clicks", 0))
        delta = post_clicks - pre_clicks
        if delta >= 0:
            continue
        out.append({
            "key": key,
            "pre_clicks": pre_clicks,
            "post_clicks": post_clicks,
            "clicks_delta": delta,
            "clicks_delta_pct": pct_delta(pre_clicks, post_clicks),
            "pre_impressions": pre_impr,
            "post_impressions": int(post_row.get("impressions", 0)),
            "pre_position": round(row.get("position", 0.0), 1),
            "post_position": round(post_row.get("position", 0.0), 1) if post_row else None,
            "dropped_out": key not in after,
        })
    out.sort(key=lambda r: r["clicks_delta"])
    return out[:top]


# ------------------------------------------------------------------------ report

def fmt_pct(value: float | None) -> str:
    if value is None:
        return "n/a"
    if value == float("inf"):
        return "new"
    return f"{value:+.1f}%"


def print_table(results: list[SiteResult]) -> None:
    width = max((len(r.site_url) for r in results), default=20)
    width = min(width, 52)
    header = f"{'PROPERTY':<{width}}  {'VERDICT':<28} {'CLICKS':>16} {'Δ':>9} {'IMPR Δ':>9} {'POS Δ':>7}"
    print(header)
    print("-" * len(header))
    for r in results:
        if r.error:
            print(f"{r.site_url[:width]:<{width}}  {'ERROR':<28} {r.error[:50]}")
            continue
        clicks = f"{r.pre.clicks:,} → {r.post.clicks:,}"
        position = f"{r.position_delta:+.1f}" if r.position_delta is not None else "n/a"
        print(
            f"{r.site_url[:width]:<{width}}  {r.verdict:<28} {clicks:>16} "
            f"{fmt_pct(r.clicks_delta_pct):>9} {fmt_pct(r.impressions_delta_pct):>9} {position:>7}"
        )


def write_csv(results: list[SiteResult], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "site_url", "permission", "verdict",
            "pre_clicks", "post_clicks", "clicks_delta_pct",
            "pre_impressions", "post_impressions", "impressions_delta_pct",
            "pre_position", "post_position", "position_delta",
            "pre_ctr", "post_ctr", "error",
        ])
        for r in results:
            writer.writerow([
                r.site_url, r.permission, r.verdict,
                r.pre.clicks, r.post.clicks,
                "" if r.clicks_delta_pct is None else round(r.clicks_delta_pct, 2),
                r.pre.impressions, r.post.impressions,
                "" if r.impressions_delta_pct is None else round(r.impressions_delta_pct, 2),
                round(r.pre.position, 2), round(r.post.position, 2),
                "" if r.position_delta is None else round(r.position_delta, 2),
                round(r.pre.ctr * 100, 2), round(r.post.ctr * 100, 2),
                r.error or "",
            ])


def print_drilldowns(results: list[SiteResult]) -> None:
    for r in results:
        if not (r.losers_pages or r.losers_queries):
            continue
        print(f"\n{'=' * 78}\n{r.site_url}  —  {r.verdict}  ({fmt_pct(r.clicks_delta_pct)} clicks)\n{'=' * 78}")
        for label, rows in (("PAGES", r.losers_pages), ("QUERIES", r.losers_queries)):
            if not rows:
                continue
            print(f"\n  Biggest {label.lower()} losses")
            for row in rows:
                gone = "  [gone from index/SERP]" if row["dropped_out"] else ""
                moved = ""
                if row["post_position"] is not None:
                    moved = f"  pos {row['pre_position']} → {row['post_position']}"
                print(f"    {row['clicks_delta']:>6}  {row['pre_clicks']:>6} → {row['post_clicks']:<6} "
                      f"{row['key'][:80]}{moved}{gone}")


# -------------------------------------------------------------------------- main

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update-start", default=DEFAULT_UPDATE_START, help="First day of the rollout (YYYY-MM-DD).")
    parser.add_argument("--update-end", default=DEFAULT_UPDATE_END, help="Last day of the rollout (YYYY-MM-DD).")
    parser.add_argument("--lag-days", type=int, default=DEFAULT_LAG_DAYS, help="Days of unfinalized data to ignore.")
    parser.add_argument("--max-window", type=int, default=DEFAULT_MAX_WINDOW, help="Longest comparison window, in days.")
    parser.add_argument("--site", action="append", help="Limit to these properties (repeatable).")
    parser.add_argument("--search-type", default="web", choices=["web", "image", "video", "news", "googleNews", "discover"])
    parser.add_argument("--hit-threshold", type=float, default=25.0, help="Click drop %% that counts as a hit.")
    parser.add_argument("--min-clicks", type=int, default=30, help="Pre-window clicks below which a site may be noise.")
    parser.add_argument("--min-impressions", type=int, default=500, help="Pre-window impressions below which a site may be noise.")
    parser.add_argument("--drilldown", type=int, default=10, help="How many hit properties to drill into (0 disables).")
    parser.add_argument("--drilldown-all", action="store_true", help="Drill into every property, hit or not.")
    parser.add_argument("--top", type=int, default=10, help="Rows per drilldown table.")
    parser.add_argument("--out-dir", type=Path, default=Path("."), help="Where to write the CSV and JSON.")
    parser.add_argument("--today", help="Override today's date (YYYY-MM-DD), for reproducible runs.")
    args = parser.parse_args()

    update_start = dt.date.fromisoformat(args.update_start)
    update_end = dt.date.fromisoformat(args.update_end)
    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
    pre, post = resolve_windows(update_start, update_end, today, args.lag_days, args.max_window)

    service = build("searchconsole", "v1", credentials=load_credentials(), cache_discovery=False)

    sites = list_sites(service)
    if args.site:
        wanted = set(args.site)
        sites = [s for s in sites if s[0] in wanted]
        missing = wanted - {s[0] for s in sites}
        for m in sorted(missing):
            print(f"warning: {m} is not readable by this account", file=sys.stderr)

    window_days = (pre[1] - pre[0]).days + 1
    print(f"Update rollout : {update_start} → {update_end}")
    print(f"Before         : {pre[0]} → {pre[1]}  ({window_days} days)")
    print(f"After          : {post[0]} → {post[1]}  ({window_days} days)")
    print(f"Properties     : {len(sites)}  (search type: {args.search_type})\n")

    results: list[SiteResult] = []
    for index, (site_url, permission) in enumerate(sites, start=1):
        print(f"[{index}/{len(sites)}] {site_url}", file=sys.stderr)
        try:
            pre_totals = totals_from_rows(query_rows(service, site_url, pre[0], pre[1], ["date"], args.search_type))
            post_totals = totals_from_rows(query_rows(service, site_url, post[0], post[1], ["date"], args.search_type))
        except HttpError as exc:
            results.append(SiteResult(site_url, permission, Totals(), Totals(), None, None, None, "ERROR",
                                      error=f"{getattr(exc.resp, 'status', '?')} {exc.reason}"))
            continue

        clicks_delta = pct_delta(pre_totals.clicks, post_totals.clicks)
        impressions_delta = pct_delta(pre_totals.impressions, post_totals.impressions)
        # Position is a rank: going up in number means going down in the results.
        position_delta = (post_totals.position - pre_totals.position) if pre_totals.impressions else None

        results.append(SiteResult(
            site_url=site_url,
            permission=permission,
            pre=pre_totals,
            post=post_totals,
            clicks_delta_pct=clicks_delta,
            impressions_delta_pct=impressions_delta,
            position_delta=position_delta,
            verdict=classify(pre_totals, post_totals, clicks_delta, impressions_delta,
                             position_delta, args.hit_threshold, args.min_clicks,
                             args.min_impressions),
        ))

    # Worst first: severity class, then clicks actually lost, then the percentage.
    # Ranking on percentage alone would float every low-traffic property to the top.
    results.sort(key=lambda r: (
        VERDICT_ORDER.get(r.verdict, 99),
        r.post.clicks - r.pre.clicks,
        r.clicks_delta_pct if r.clicks_delta_pct is not None else 0.0,
    ))

    hit_verdicts = {"SEVERE HIT", "HIT", "VISIBILITY DOWN"}
    to_drill = results if args.drilldown_all else [r for r in results if r.verdict in hit_verdicts][:args.drilldown]
    for result in to_drill:
        if result.error:
            continue
        print(f"drilldown: {result.site_url}", file=sys.stderr)
        try:
            result.losers_pages = losers(service, result.site_url, "page", pre, post, args.search_type, args.top)
            result.losers_queries = losers(service, result.site_url, "query", pre, post, args.search_type, args.top)
        except HttpError as exc:
            print(f"  drilldown failed: {exc}", file=sys.stderr)

    print()
    print_table(results)
    print_drilldowns(results)

    counts: dict[str, int] = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    print("\nSummary: " + ", ".join(f"{v} {k.lower()}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1])))

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp = today.isoformat()
    csv_path = args.out_dir / f"gsc-audit-{stamp}.csv"
    json_path = args.out_dir / f"gsc-audit-{stamp}.json"
    write_csv(results, csv_path)
    json_path.write_text(json.dumps({
        "generated": stamp,
        "update": {"start": update_start.isoformat(), "end": update_end.isoformat()},
        "windows": {
            "pre": [pre[0].isoformat(), pre[1].isoformat()],
            "post": [post[0].isoformat(), post[1].isoformat()],
        },
        "results": [asdict(r) for r in results],
    }, indent=2))
    print(f"\nWrote {csv_path} and {json_path}")
    print("Manual actions and security issues are not exposed by any API — check those in the UI "
          "for anything flagged SEVERE HIT.")


if __name__ == "__main__":
    main()
