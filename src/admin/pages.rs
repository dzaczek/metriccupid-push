//! Server-rendered admin pages: plain HTML, one external stylesheet, inline
//! SVG charts, no JavaScript. Every dynamic value goes through [`esc`].

use std::fmt::Write as _;

use std::net::IpAddr;

use super::queries::{
    AuditRow, Count, EventRow, Gateway, GatewayDetail, GatewayRow, GroupDetail, GroupFilter,
    GroupRow, Overview, Pushes, RevokedRow, Security, Series,
};
use crate::controls::{LimitKind, ManualBan, LIMIT_KEYS};

/// HTML-escape text and attribute values.
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

/// Percent-encode a query value.
fn qv(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub fn fmt_ts(ts: u64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(ts as i64) {
        Ok(t) => format!("{} {:02}:{:02}Z", t.date(), t.hour(), t.minute()),
        Err(_) => "-".into(),
    }
}

fn fmt_date(ts: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp(ts as i64)
        .map(|t| t.date().to_string())
        .unwrap_or_else(|_| "-".into())
}

pub fn fmt_dur(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        3600..=86_399 => format!("{}h {}m", secs / 3600, secs % 3600 / 60),
        _ => format!("{}d {}h", secs / 86_400, secs % 86_400 / 3600),
    }
}

fn ago(now: u64, ts: Option<u64>) -> String {
    match ts {
        Some(t) if t <= now => format!("{} ago", fmt_dur(now - t)),
        Some(t) => fmt_ts(t),
        None => "never".into(),
    }
}

pub fn fmt_bytes(b: u64) -> String {
    match b {
        0..=1023 => format!("{b} B"),
        1024..=1_048_575 => format!("{:.1} KB", b as f64 / 1024.0),
        1_048_576..=1_073_741_823 => format!("{:.1} MB", b as f64 / 1_048_576.0),
        _ => format!("{:.2} GB", b as f64 / 1_073_741_824.0),
    }
}

fn opt(s: &Option<String>) -> String {
    s.as_deref().map_or_else(|| "-".to_string(), esc)
}

// ----------------------------------------------------------------- charts ---

/// Stacked bar chart of a series; `label` turns a point label into the
/// tooltip / axis text.
pub fn bar_chart(s: &Series, label: impl Fn(&str) -> String) -> String {
    let n = s.points.len().max(1);
    let max = s
        .points
        .iter()
        .map(|p| p.1.iter().sum::<u64>())
        .max()
        .unwrap_or(0)
        .max(1);
    // Labels are HTML around the SVG: SVG text would stretch with it.
    let (w, h, top) = (n * 12, 100.0f64, 2.0f64);
    let mut o = format!(r#"<div class="ymax">{max}</div>"#);
    let _ = write!(
        o,
        r#"<svg class="chart" viewBox="0 0 {w} 103" preserveAspectRatio="none" role="img"><line class="axis" x1="0" y1="{y}" x2="{w}" y2="{y}"/>"#,
        y = top + h
    );
    for (i, (lbl, vals)) in s.points.iter().enumerate() {
        let x = i * 12 + 1;
        let tip: Vec<String> = s
            .names
            .iter()
            .zip(vals)
            .map(|(n, v)| format!("{n}: {v}"))
            .collect();
        let _ = write!(
            o,
            "<g><title>{}  {}</title>",
            esc(&label(lbl)),
            esc(&tip.join(", "))
        );
        let mut y = top + h;
        for (k, v) in vals.iter().enumerate() {
            if *v == 0 {
                continue;
            }
            let bh = (*v as f64 / max as f64 * h).max(0.8);
            y -= bh;
            let _ = write!(
                o,
                r#"<rect class="s{k}" x="{x}" y="{y:.2}" width="10" height="{bh:.2}"/>"#
            );
        }
        // Invisible full-height target so the tooltip works on empty days.
        let _ = write!(
            o,
            r#"<rect class="hit" x="{x}" y="{top}" width="10" height="{h}"/></g>"#
        );
    }
    o.push_str("</svg>");
    if let (Some(first), Some(last)) = (s.points.first(), s.points.last()) {
        let _ = write!(
            o,
            r#"<div class="xaxis"><span>{}</span><span>{}</span></div>"#,
            esc(&label(&first.0)),
            esc(&label(&last.0))
        );
    }
    if s.names.len() > 1 {
        o.push_str(r#"<div class="legend">"#);
        for (k, name) in s.names.iter().enumerate() {
            let _ = write!(
                o,
                r#"<span><svg viewBox="0 0 10 10" class="sw"><rect class="s{k}" width="10" height="10"/></svg>{} ({})</span>"#,
                esc(name),
                s.total(k)
            );
        }
        o.push_str("</div>");
    }
    o
}

fn day_label(d: &str) -> String {
    d.get(5..).unwrap_or(d).to_string()
}

fn hour_label(ts: &str) -> String {
    ts.parse().map(fmt_ts).unwrap_or_default()
}

/// Top-N list with proportional bars.
pub fn count_table(title: &str, rows: &[Count]) -> String {
    let mut o = format!("<h3>{}</h3>", esc(title));
    if rows.is_empty() {
        o.push_str(r#"<p class="muted">No data.</p>"#);
        return o;
    }
    let max = rows.iter().map(|r| r.count).max().unwrap_or(1).max(1);
    o.push_str(r#"<table class="counts">"#);
    for r in rows {
        let pct = r.count as f64 / max as f64 * 100.0;
        let _ = write!(
            o,
            r#"<tr><td>{}</td><td class="num">{}</td><td class="barcell"><svg class="hbar" viewBox="0 0 100 6" preserveAspectRatio="none"><rect class="s0" width="{pct:.1}" height="6"/></svg></td></tr>"#,
            if r.key.is_empty() {
                "-".into()
            } else {
                esc(&r.key)
            },
            r.count
        );
    }
    o.push_str("</table>");
    o
}

fn tile(label: &str, value: &str, sub: &str) -> String {
    format!(
        r#"<div class="tile"><div class="tl">{}</div><div class="tv">{}</div><div class="ts">{}</div></div>"#,
        esc(label),
        esc(value),
        esc(sub)
    )
}

fn events_table(now: u64, rows: &[EventRow], with_ip: bool) -> String {
    if rows.is_empty() {
        return r#"<p class="muted">No events.</p>"#.into();
    }
    let mut o = String::from(
        r#"<div class="scroll"><table><tr><th>Time</th><th>Kind</th><th>Route</th><th>Status</th><th>Outcome</th><th>Detail</th><th>ms</th><th>Client</th>"#,
    );
    if with_ip {
        o.push_str("<th>Network</th>");
    }
    o.push_str("<th>Country</th></tr>");
    for e in rows {
        let detail = match (&e.detail, &e.apns_reason, e.duration_s) {
            (_, Some(r), _) => format!(
                "{} {}",
                e.apns_status.map(|s| s.to_string()).unwrap_or_default(),
                r
            ),
            (Some(d), _, Some(s)) => format!("{d} ({})", fmt_dur(s)),
            (None, None, Some(s)) => fmt_dur(s),
            (Some(d), _, _) => d.clone(),
            _ => String::new(),
        };
        let _ = write!(
            o,
            r#"<tr><td title="{}">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class="num">{}</td><td>{}</td>"#,
            fmt_ts(e.ts),
            esc(&ago(now, Some(e.ts))),
            esc(&e.kind),
            opt(&e.route),
            e.status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into()),
            opt(&e.outcome),
            esc(&detail),
            e.latency_ms.map(|l| l.to_string()).unwrap_or_default(),
            opt(&e.app_version),
        );
        if with_ip {
            let _ = write!(o, "<td>{}</td>", opt(&e.ip_prefix));
        }
        let _ = write!(o, "<td>{}</td></tr>", opt(&e.country));
    }
    o.push_str("</table></div>");
    o
}

// ----------------------------------------------------------------- layout ---

pub struct Page<'a> {
    pub title: &'a str,
    pub nav: &'a str,
    /// Logout form token; `None` on the login page.
    pub csrf: Option<&'a str>,
    /// The page path, for the auto-refresh toggle and JSON link.
    pub path: &'a str,
    pub json: Option<&'a str>,
    pub refresh: bool,
    pub version: &'a str,
}

pub fn layout(p: &Page<'_>, body: &str) -> String {
    let mut o = String::from("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    o.push_str(r#"<meta name="viewport" content="width=device-width, initial-scale=1">"#);
    o.push_str(r#"<meta name="robots" content="noindex, nofollow">"#);
    if p.refresh {
        o.push_str(r#"<meta http-equiv="refresh" content="30">"#);
    }
    let _ = write!(
        o,
        r#"<title>{} - MetricCupid Push admin</title><link rel="stylesheet" href="/admin/style.css"></head><body>"#,
        esc(p.title)
    );
    if let Some(csrf) = p.csrf {
        o.push_str(r#"<header><nav><span class="brand">MetricCupid Push</span>"#);
        for (key, href, label) in [
            ("overview", "/admin/", "Overview"),
            ("groups", "/admin/groups", "Groups"),
            ("pushes", "/admin/pushes", "Pushes"),
            ("security", "/admin/security", "Security"),
            ("bans", "/admin/bans", "Bans"),
            ("gateway", "/admin/gateway", "Gateway"),
            ("licences", "/admin/licences", "Licences"),
            ("limits", "/admin/limits", "Limits"),
            ("audit", "/admin/audit", "Audit log"),
        ] {
            let cls = if key == p.nav { r#" class="on""# } else { "" };
            let _ = write!(o, r#"<a href="{href}"{cls}>{label}</a>"#);
        }
        let _ = write!(
            o,
            r#"<form method="post" action="/admin/logout" class="logout"><input type="hidden" name="csrf" value="{}"><button type="submit">Log out</button></form></nav></header>"#,
            esc(csrf)
        );
    }
    let _ = write!(o, "<main><h1>{}</h1>{body}</main><footer>", esc(p.title));
    if p.csrf.is_some() {
        let toggle = if p.refresh {
            format!(r#"<a href="{}">Auto-refresh: on</a>"#, esc(p.path))
        } else {
            format!(
                r#"<a href="{}?refresh=1">Auto-refresh: off</a>"#,
                esc(p.path)
            )
        };
        o.push_str(&toggle);
        if let Some(j) = p.json {
            let _ = write!(o, r#" · <a href="{}">JSON</a>"#, esc(j));
        }
        o.push_str(r#" · <a href="/admin/export/daily.csv">CSV (daily aggregates)</a> · "#);
    }
    let _ = write!(
        o,
        "metriccupid-push {} · metadata only, content is end-to-end encrypted</footer></body></html>",
        esc(p.version)
    );
    o
}

pub fn login(error: Option<&str>, csrf: &str) -> String {
    let mut o = String::new();
    if let Some(e) = error {
        let _ = write!(o, r#"<p class="error" role="alert">{}</p>"#, esc(e));
    }
    let _ = write!(
        o,
        r#"<form method="post" action="/admin/login" class="login" autocomplete="off">
<input type="hidden" name="csrf" value="{}">
<label>User <input name="user" autocomplete="username" required maxlength="64"></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required maxlength="256"></label>
<label>Authenticator code <input name="totp" inputmode="numeric" pattern="[0-9]{{6}}" autocomplete="one-time-code" required maxlength="6"></label>
<button type="submit">Log in</button></form>"#,
        esc(csrf)
    );
    o
}

// ------------------------------------------------------------------ pages ---

/// Live values that do not come from the database.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Runtime {
    pub version: &'static str,
    pub uptime_secs: u64,
    pub rss_bytes: Option<u64>,
    pub db_bytes: u64,
    pub macs_online: usize,
    pub latency_p50_ms: Option<u32>,
    pub latency_p95_ms: Option<u32>,
    pub metrics_dropped: u64,
    pub admin_sessions: usize,
    pub mode: &'static str,
    pub apns_mode: &'static str,
    pub licence_mode: &'static str,
    pub licence_grace_until: Option<u64>,
    pub trust_proxy: &'static str,
}

pub fn overview(now: u64, o: &Overview, rt: &Runtime) -> String {
    let mut b = String::from(r#"<section class="tiles">"#);
    b += &tile(
        "Groups",
        &o.groups_total.to_string(),
        &format!(
            "active 24h {} · 7d {} · 30d {}",
            o.active_24h, o.active_7d, o.active_30d
        ),
    );
    let kinds: Vec<String> = o
        .devices_by_kind
        .iter()
        .map(|c| format!("{} {}", c.key, c.count))
        .collect();
    b += &tile(
        "Devices",
        &o.devices_by_kind
            .iter()
            .map(|c| c.count)
            .sum::<u64>()
            .to_string(),
        &format!("{} · Macs online now {}", kinds.join(" · "), rt.macs_online),
    );
    let lic: Vec<String> = o
        .licences
        .iter()
        .map(|c| format!("{} {}", c.key, c.count))
        .collect();
    b += &tile(
        "Licences",
        &o.licences.iter().map(|c| c.count).sum::<u64>().to_string(),
        &lic.iter()
            .cloned()
            .chain([format!("unlicensed {}", o.unlicensed_groups)])
            .collect::<Vec<_>>()
            .join(" · "),
    );
    b += &tile(
        "Pushes (30 d)",
        &o.pushes_daily.total(0).to_string(),
        &format!(
            "failed {} · unregistered {}",
            o.pushes_daily.total(1),
            o.pushes_daily.total(2)
        ),
    );
    let total_http: u64 = (0..4).map(|i| o.http_daily.total(i)).sum::<u64>().max(1);
    let pct = |i: usize| o.http_daily.total(i) as f64 / total_http as f64 * 100.0;
    b += &tile(
        "HTTP errors (14 d)",
        &format!("{:.1}% 4xx", pct(1) + pct(2)),
        &format!("429 {:.1}% · 5xx {:.2}%", pct(2), pct(3)),
    );
    b += &tile(
        "Latency",
        &rt.latency_p50_ms
            .map_or("-".into(), |v| format!("p50 {v} ms")),
        &rt.latency_p95_ms.map_or("last 4096 requests".into(), |v| {
            format!("p95 {v} ms · last 4096 requests")
        }),
    );
    b += &tile(
        "WebSocket (7 d)",
        &o.ws_sessions_7d.to_string(),
        &o.ws_median_secs_7d.map_or("sessions".into(), |s| {
            format!("sessions · median {}", fmt_dur(s))
        }),
    );
    b += &tile(
        "Snapshots (30 d)",
        &o.snapshots_30d.to_string(),
        &format!("stored · {}", fmt_bytes(o.snapshot_bytes_30d)),
    );
    b += &tile(
        "Server",
        &format!("v{}", rt.version),
        &format!(
            "up {} · RSS {} · DB {}",
            fmt_dur(rt.uptime_secs),
            rt.rss_bytes.map_or("n/a".into(), fmt_bytes),
            fmt_bytes(rt.db_bytes)
        ),
    );
    b += &tile(
        "Configuration",
        rt.mode,
        &format!(
            "APNs {} · licence {}{} · proxy {}",
            rt.apns_mode,
            rt.licence_mode,
            rt.licence_grace_until
                .map_or(String::new(), |g| format!(" (grace until {})", fmt_date(g))),
            rt.trust_proxy
        ),
    );
    b += &tile(
        "Metrics",
        &o.event_rows.to_string(),
        &format!("raw events stored · dropped {}", rt.metrics_dropped),
    );
    b.push_str("</section>");

    b += r#"<section class="grid">"#;
    b += &format!(
        "<div class=\"card\"><h2>Pushes per hour (48 h)</h2>{}</div>",
        bar_chart(&o.pushes_hourly, hour_label)
    );
    b += &format!(
        "<div class=\"card\"><h2>Pushes per day (30 d)</h2>{}</div>",
        bar_chart(&o.pushes_daily, day_label)
    );
    b += &format!(
        "<div class=\"card\"><h2>Messages, commands, activity updates per day</h2>{}</div>",
        bar_chart(&o.traffic_daily, day_label)
    );
    b += &format!(
        "<div class=\"card\"><h2>HTTP responses per day (14 d)</h2>{}</div>",
        bar_chart(&o.http_daily, day_label)
    );
    b += &format!(
        "<div class=\"card\"><h2>New groups per day</h2>{}</div>",
        bar_chart(&o.new_groups, day_label)
    );
    b += &format!(
        "<div class=\"card\">{}{}</div>",
        count_table("Top countries (30 d requests)", &o.top_countries),
        count_table("APNs errors (30 d)", &o.apns_reasons)
    );
    b.push_str("</section>");
    let _ = now;
    b
}

pub fn groups(now: u64, rows: &[GroupRow], f: &GroupFilter) -> String {
    let sel = |name: &str, cur: &str, opts: &[(&str, &str)]| -> String {
        let mut s = format!(
            r#"<label>{} <select name="{}">"#,
            esc(name),
            esc(&name.to_lowercase())
        );
        for (v, l) in opts {
            let on = if *v == cur { " selected" } else { "" };
            let _ = write!(s, r#"<option value="{}"{on}>{}</option>"#, esc(v), esc(l));
        }
        s + "</select></label>"
    };
    let mut b = String::from(r#"<form method="get" action="/admin/groups" class="filters">"#);
    b += &sel(
        "Active",
        &f.active,
        &[
            ("", "any"),
            ("24h", "24 h"),
            ("7d", "7 d"),
            ("30d", "30 d"),
            ("inactive", "inactive 30 d"),
        ],
    );
    b += &sel(
        "Licence",
        &f.licence,
        &[
            ("", "any"),
            ("licensed", "licensed"),
            ("founder", "founder"),
            ("none", "none"),
        ],
    );
    b += &sel(
        "Suspended",
        &f.suspended,
        &[("", "any"), ("yes", "suspended"), ("no", "not suspended")],
    );
    let _ = write!(
        b,
        r#"<label>Country <input name="country" value="{}" maxlength="2" size="3"></label><label>Group id <input name="q" value="{}" maxlength="22" size="12"></label>"#,
        esc(&f.country),
        esc(&f.q)
    );
    b += &sel(
        "Sort",
        &f.sort,
        &[
            ("", "created"),
            ("last_active", "last active"),
            ("requests", "requests 30 d"),
            ("pushes", "pushes 30 d"),
            ("devices", "devices"),
        ],
    );
    b += &sel("Order", &f.order, &[("", "desc"), ("asc", "asc")]);
    b += r#"<button type="submit">Apply</button></form>"#;
    let _ = write!(
        b,
        r#"<p class="muted">{} groups shown (max {}).</p>"#,
        rows.len(),
        super::queries::MAX_GROUP_ROWS
    );
    b += r#"<div class="scroll"><table><tr><th>Group</th><th>Created</th><th>Last active</th><th>Macs</th><th>Phones</th><th>Licence</th><th>Country</th><th>Requests 30 d</th><th>Pushes 30 d</th><th>State</th></tr>"#;
    for g in rows {
        let lic = match (&g.tier, &g.environment) {
            (Some(t), Some(e)) => format!("{t} / {e}"),
            _ => "-".into(),
        };
        let _ = write!(
            b,
            r#"<tr><td><a href="/admin/groups/{}"><code>{}</code></a></td><td>{}</td><td>{}</td><td class="num">{}</td><td class="num">{}</td><td>{}</td><td>{}</td><td class="num">{}</td><td class="num">{}</td><td>{}</td></tr>"#,
            qv(&g.group_id),
            esc(&g.group_id),
            fmt_date(g.created_at),
            esc(&ago(now, g.last_active)),
            g.macs,
            g.phones,
            esc(&lic),
            opt(&g.country),
            g.requests_30d,
            g.pushes_30d,
            if g.suspended {
                r#"<span class="error">suspended</span>"#
            } else {
                "active"
            }
        );
    }
    b.push_str("</table></div>");
    b
}

pub fn group_detail(now: u64, g: &GroupDetail, csrf: &str) -> String {
    let mut b = format!(
        r#"<p><code>{}</code> · created {} · mailbox {} messages · {} queued commands</p>"#,
        esc(&g.group_id),
        fmt_ts(g.created_at),
        g.mailbox_messages,
        g.queued_commands
    );
    b += "<h2>State</h2>";
    let gid = qv(&g.group_id);
    match &g.suspension {
        Some(sp) => {
            let _ = write!(
                b,
                r#"<p><span class="error">Suspended</span> {} by {}: {}</p>"#,
                fmt_ts(sp.suspended_at),
                esc(&sp.actor),
                esc(&sp.reason)
            );
            b += &action_form(
                &format!("/admin/groups/{gid}/unsuspend"),
                csrf,
                "",
                "Unsuspend",
            );
        }
        None => {
            b += r#"<p>Active. Suspending refuses every signed request with <code>403 group_suspended</code>, closes its streams and stops all pushes; data is kept.</p>"#;
            b += &action_form(
                &format!("/admin/groups/{gid}/suspend"),
                csrf,
                &reason_field(),
                "Suspend",
            );
        }
    }
    if let Some(l) = g.gateway_licensed {
        let _ = write!(
            b,
            r#"<p>Gateway group (stored licensed flag: {}). <a href="/admin/gateway/{gid}">Gateway details</a></p>"#,
            if l { "yes" } else { "no" }
        );
    }
    b += "<h2>Licence</h2>";
    match &g.licence {
        Some(l) => {
            if l.revoked {
                b += r#"<p class="error">This purchase is revoked: the group is treated as unlicensed.</p>"#;
            }
            let _ = write!(
                b,
                "<table><tr><th>Tier</th><th>Environment</th><th>Original purchase</th><th>Original version</th><th>Platform</th><th>Attached</th><th>Verified</th></tr><tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr></table>",
                esc(&l.tier),
                esc(&l.environment),
                l.original_purchase_date.map_or("-".into(), |d| fmt_date(d / 1000)),
                opt(&l.original_application_version),
                opt(&l.original_platform),
                fmt_ts(l.attached_at),
                fmt_ts(l.verified_at)
            );
        }
        None => b += r#"<p class="muted">No licence.</p>"#,
    }
    b += r#"<h2>Devices</h2><div class="scroll"><table><tr><th>Kind</th><th>Name</th><th>Device</th><th>APNs env</th><th>Token</th><th>Online</th><th>Last seen</th><th>Last request</th><th>App version</th><th>Country</th><th>Created</th></tr>"#;
    for d in &g.devices {
        let _ = write!(
            b,
            r#"<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
            esc(&d.kind),
            esc(&d.name),
            esc(&d.device_id),
            esc(&d.apns_env),
            if d.has_token { "yes" } else { "no" },
            match d.online {
                Some(true) => r#"<span class="ok">online</span>"#,
                Some(false) => "offline",
                None => "-",
            },
            if d.kind == "mac" {
                esc(&ago(now, d.last_seen))
            } else {
                "-".into()
            },
            esc(&ago(now, d.last_active)),
            opt(&d.app_version),
            opt(&d.country),
            fmt_date(d.created_at)
        );
    }
    b += "</table></div>";
    let _ = write!(
        b,
        "<div class=\"card\"><h2>Daily activity (30 d)</h2>{}</div>",
        bar_chart(&g.activity_daily, day_label)
    );
    b += "<h2>App versions seen</h2>";
    if g.app_versions.is_empty() {
        b += r#"<p class="muted">None yet (clients send X-MC-Client).</p>"#;
    } else {
        b += "<table><tr><th>Version</th><th>First seen</th><th>Last seen</th><th>Events</th></tr>";
        for v in &g.app_versions {
            let _ = write!(
                b,
                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td class="num">{}</td></tr>"#,
                esc(&v.app_version),
                fmt_ts(v.first_seen),
                fmt_ts(v.last_seen),
                v.events
            );
        }
        b += "</table>";
    }
    b += "<h2>Recent events</h2>";
    b += &events_table(now, &g.recent_events, false);
    b
}

pub fn pushes(now: u64, p: &Pushes, apns_mode: &str) -> String {
    let mut b = format!(
        r#"<p>APNs mode: <b>{}</b></p><section class="grid">"#,
        esc(apns_mode)
    );
    let _ = write!(
        b,
        "<div class=\"card\"><h2>Pushes per day by type (30 d)</h2>{}</div>",
        bar_chart(&p.daily, day_label)
    );
    let _ = write!(
        b,
        "<div class=\"card\"><h2>Unregistered tokens removed per day</h2>{}</div>",
        bar_chart(&p.unregistered_daily, day_label)
    );
    let _ = write!(
        b,
        "<div class=\"card\">{}{}</div>",
        count_table("Type and outcome (30 d)", &p.by_type),
        count_table("Sender / APNs environment (30 d)", &p.by_via_env)
    );
    let _ = write!(
        b,
        "<div class=\"card\">{}</div>",
        count_table("Failure reasons (30 d)", &p.reasons)
    );
    b += "</section><h2>Recent failures</h2>";
    b += &events_table(now, &p.recent_failures, false);
    b
}

pub fn security(now: u64, s: &Security, sessions: usize) -> String {
    let mut b = format!(
        r#"<p>Active admin sessions: {sessions}. Networks are truncated (/24, /48); full client IPs are never stored.</p><section class="grid">"#
    );
    let _ = write!(
        b,
        "<div class=\"card\"><h2>Per day (30 d)</h2>{}</div>",
        bar_chart(&s.daily, day_label)
    );
    let _ = write!(
        b,
        "<div class=\"card\">{}{}</div>",
        count_table("Rate limits (route, reason)", &s.rate_limits),
        count_table("Auth failures by route", &s.auth_failures_by_route)
    );
    let _ = write!(
        b,
        "<div class=\"card\">{}{}</div>",
        count_table("Top offending networks", &s.top_prefixes),
        count_table("Top offending countries", &s.top_countries)
    );
    let _ = write!(
        b,
        "<div class=\"card\">{}{}</div>",
        count_table("Licence verifications (30 d)", &s.licence_outcomes),
        count_table("Licence results by reason (raw events)", &s.licence_reasons)
    );
    b += "</section><h2>Recent licence verifications</h2>";
    b += &events_table(now, &s.licence_events, true);
    b += "<h2>Bans (30 d)</h2>";
    b += &events_table(now, &s.bans, true);
    b += "<h2>Admin logins</h2>";
    b += &events_table(now, &s.admin_logins, true);
    b
}

// ------------------------------------------------------------ management ---

/// A POST form for one panel action: CSRF token, the action's own fields,
/// and a fresh authenticator code (step-up).
pub fn action_form(action: &str, csrf: &str, fields: &str, button: &str) -> String {
    format!(
        r#"<form method="post" action="{}" class="action" autocomplete="off"><input type="hidden" name="csrf" value="{}">{fields}<label>Code <input name="totp" inputmode="numeric" pattern="[0-9]{{6}}" autocomplete="one-time-code" required maxlength="6" size="7"></label><button type="submit">{}</button></form>"#,
        esc(action),
        esc(csrf),
        esc(button)
    )
}

fn hidden(name: &str, value: &str) -> String {
    format!(
        r#"<input type="hidden" name="{}" value="{}">"#,
        esc(name),
        esc(value)
    )
}

fn reason_field() -> String {
    r#"<label>Reason <input name="reason" required maxlength="200" size="24"></label>"#.into()
}

/// The outcome of a panel action.
pub fn result(ok: bool, message: &str, back: &str) -> String {
    format!(
        r#"<p class="{}" role="status">{}</p><p><a href="{}">Back</a></p>"#,
        if ok { "ok" } else { "error" },
        esc(message),
        esc(back)
    )
}

pub fn bans(now: u64, manual: &[ManualBan], auto: &[(IpAddr, u64)], csrf: &str) -> String {
    let mut b = String::from(
        r#"<p>Manual bans are kept across restarts and checked before anything else on every public request (<code>429</code> with <code>Retry-After</code>). Automatic bans come from repeated authentication failures and live in memory only.</p><h2>Ban an IP or prefix</h2>"#,
    );
    b += &action_form(
        "/admin/bans/add",
        csrf,
        &format!(
            r#"<label>IP or CIDR <input name="target" required maxlength="64" size="22" placeholder="192.0.2.0/24"></label><label>Duration <select name="duration">{}</select></label>{}"#,
            ["15m", "1h", "6h", "1d", "7d", "30d"]
                .iter()
                .map(|d| format!(r#"<option value="{d}">{d}</option>"#))
                .collect::<String>(),
            reason_field()
        ),
        "Ban",
    );
    b += r#"<p class="muted">IPv4 /16 or longer, IPv6 /32 or longer; 15 minutes to 30 days.</p>"#;
    let _ = write!(b, "<h2>Manual bans ({})</h2>", manual.len());
    if manual.is_empty() {
        b += r#"<p class="muted">None.</p>"#;
    } else {
        b += r#"<div class="scroll"><table><tr><th>Prefix</th><th>Expires</th><th>Reason</th><th>By</th><th>Since</th><th></th></tr>"#;
        for m in manual {
            let net = m.net.to_string();
            let _ = write!(
                b,
                r#"<tr><td><code>{}</code></td><td title="{}">in {}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                esc(&net),
                fmt_ts(m.until),
                fmt_dur(m.until.saturating_sub(now)),
                esc(&m.reason),
                esc(&m.actor),
                fmt_ts(m.created_at),
                action_form("/admin/bans/remove", csrf, &hidden("target", &net), "Lift")
            );
        }
        b += "</table></div>";
    }
    let _ = write!(b, "<h2>Automatic bans ({})</h2>", auto.len());
    if auto.is_empty() {
        b += r#"<p class="muted">None.</p>"#;
    } else {
        b += r#"<div class="scroll"><table><tr><th>Address (IPv6: /64)</th><th>Expires</th><th></th></tr>"#;
        for (ip, left) in auto {
            let ip = ip.to_string();
            let _ = write!(
                b,
                r#"<tr><td><code>{}</code></td><td>in {}</td><td>{}</td></tr>"#,
                esc(&ip),
                fmt_dur(*left),
                action_form("/admin/bans/unban", csrf, &hidden("target", &ip), "Unban")
            );
        }
        b += "</table></div>";
    }
    b
}

/// Effective gateway quotas, for the gateway pages.
pub struct GatewayQuotas {
    pub open: bool,
    pub require_licence: bool,
    pub per_hour: u32,
    pub max_tokens: u32,
    pub max_groups: u32,
}

fn gateway_state(r: &GatewayRow) -> String {
    let mut parts = vec![if r.licensed {
        "licensed".to_string()
    } else if r.licensed_flag {
        "licence revoked".to_string()
    } else {
        "unlicensed".to_string()
    }];
    if r.suspended {
        parts.push("suspended".into());
    }
    parts.join(", ")
}

pub fn gateway(now: u64, g: &Gateway, q: &GatewayQuotas) -> String {
    let mut b = format!(
        r#"<p>Gateway <b>{}</b>{} · {} of {} groups · per group {} pushes per hour (licensed twice) · {} tokens per group. Change these on the <a href="/admin/limits">Limits</a> page.</p>"#,
        if q.open { "open" } else { "closed" },
        if q.require_licence {
            " (licence required)"
        } else {
            ""
        },
        g.total,
        q.max_groups,
        q.per_hour,
        q.max_tokens
    );
    b += &count_table("Refusals (24 h)", &g.refusals_24h);
    let _ = write!(
        b,
        r#"<h2>Groups</h2><p class="muted">{} shown (max {}). "Sent 1 h" counts pushes answered <code>sent</code> in the last hour (raw events): the per-group hourly bucket itself cannot be read without using it up.</p>"#,
        g.rows.len(),
        super::queries::MAX_GROUP_ROWS
    );
    b += r#"<div class="scroll"><table><tr><th>Group</th><th>Joined</th><th>State</th><th>Tokens</th><th>Last use</th><th>Sent 1 h</th><th>Refused 24 h</th></tr>"#;
    for r in &g.rows {
        let quota = if r.licensed {
            u64::from(q.per_hour) * 2
        } else {
            u64::from(q.per_hour)
        };
        let _ = write!(
            b,
            r#"<tr><td><a href="/admin/gateway/{}"><code>{}</code></a></td><td>{}</td><td>{}</td><td class="num">{} / {}</td><td>{}</td><td class="num">{} / {}</td><td class="num">{}</td></tr>"#,
            qv(&r.group_id),
            esc(&r.group_id),
            fmt_date(r.created_at),
            esc(&gateway_state(r)),
            r.tokens,
            q.max_tokens,
            esc(&ago(now, r.last_used)),
            r.sent_1h,
            quota,
            r.refused_24h
        );
    }
    b += "</table></div><h2>Recent refusals</h2>";
    b += &events_table(now, &g.recent_refusals, false);
    b
}

pub fn gateway_detail(now: u64, d: &GatewayDetail, q: &GatewayQuotas, csrf: &str) -> String {
    let r = &d.row;
    let gid = qv(&r.group_id);
    let mut b = format!(
        r#"<p><a href="/admin/groups/{gid}"><code>{}</code></a> · joined {} · {} · {} of {} tokens · last use {} · sent in the last hour {}</p>"#,
        esc(&r.group_id),
        fmt_ts(r.created_at),
        esc(&gateway_state(r)),
        r.tokens,
        q.max_tokens,
        esc(&ago(now, r.last_used)),
        r.sent_1h
    );
    b += "<h2>Remove from the gateway</h2><p>Deletes the membership and unbinds every token; the group's next push gets <code>403 not_gateway_group</code>. A new registration with <code>gateway: true</code> adds it again while the gateway is open: suspend the group to keep it out.</p>";
    b += &action_form(
        &format!("/admin/gateway/{gid}/remove"),
        csrf,
        "",
        "Remove from gateway",
    );
    let _ = write!(
        b,
        r#"<h2>Bound tokens ({})</h2><p class="muted">Tokens are shown as a fingerprint (first 12 hex digits of their SHA-256).</p>"#,
        d.tokens.len()
    );
    if d.tokens.is_empty() {
        b += r#"<p class="muted">None.</p>"#;
    } else {
        b += "<table><tr><th>Token</th><th>Last used</th><th></th></tr>";
        for t in &d.tokens {
            let _ = write!(
                b,
                r#"<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>"#,
                esc(&t.fp),
                esc(&ago(now, Some(t.last_used))),
                action_form(
                    &format!("/admin/gateway/{gid}/unbind"),
                    csrf,
                    &hidden("token", &t.fp),
                    "Unbind"
                )
            );
        }
        b += "</table>";
    }
    b += "<h2>Recent refusals</h2>";
    b += &events_table(now, &d.recent_refusals, false);
    b
}

pub fn licences(rows: &[RevokedRow], config: &[(String, u64)], csrf: &str) -> String {
    let mut b = String::from(
        r#"<p>A revoked purchase is refused at registration and <code>PUT /v2/licence</code>, and groups it is already attached to are treated as unlicensed at once: hosted groups follow <code>LICENCE_MODE</code>, gateway groups lose the licensed quotas (and are refused with <code>GATEWAY_REQUIRE_LICENCE</code>). Purchase ids are never shown: rows carry a fingerprint (first 12 hex digits of the id's SHA-256).</p><h2>Revoke a purchase</h2>"#,
    );
    b += &action_form(
        "/admin/licences/revoke",
        csrf,
        &format!(
            r#"<label>Purchase id (appTransactionId) <input name="tx" required maxlength="128" size="24"></label>{}"#,
            reason_field()
        ),
        "Revoke",
    );
    let _ = write!(b, "<h2>Revoked in the panel ({})</h2>", rows.len());
    if rows.is_empty() {
        b += r#"<p class="muted">None.</p>"#;
    } else {
        b += r#"<div class="scroll"><table><tr><th>Purchase</th><th>Revoked</th><th>Reason</th><th>By</th><th>Groups attached</th><th></th></tr>"#;
        for r in rows {
            let _ = write!(
                b,
                r#"<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td class="num">{}</td><td>{}</td></tr>"#,
                esc(&r.fp),
                fmt_ts(r.revoked_at),
                esc(&r.reason),
                esc(&r.actor),
                r.groups,
                action_form(
                    "/admin/licences/restore",
                    csrf,
                    &hidden("fp", &r.fp),
                    "Restore"
                )
            );
        }
        b += "</table></div>";
    }
    let _ = write!(
        b,
        "<h2>Revoked by <code>LICENCE_REVOKED_TX</code> ({})</h2>",
        config.len()
    );
    if config.is_empty() {
        b += r#"<p class="muted">None.</p>"#;
    } else {
        b += r#"<p class="muted">Set in the environment; remove them there.</p><table><tr><th>Purchase</th><th>Groups attached</th></tr>"#;
        for (fp, n) in config {
            let _ = write!(
                b,
                r#"<tr><td><code>{}</code></td><td class="num">{n}</td></tr>"#,
                esc(fp)
            );
        }
        b += "</table>";
    }
    b
}

/// One row of the Limits page.
pub struct LimitRow {
    pub key: &'static str,
    pub config: u32,
    pub overridden: Option<u32>,
}

fn limit_value(kind: LimitKind, v: u32) -> String {
    match kind {
        LimitKind::Switch if v != 0 => "true".into(),
        LimitKind::Switch => "false".into(),
        LimitKind::Number => v.to_string(),
    }
}

pub fn limits(rows: &[LimitRow], csrf: &str) -> String {
    let mut b = String::from(
        r#"<p>Overrides apply at once, without a restart, and are kept across restarts until reset. A changed rate replaces its limiter, so its buckets start full again. Each override must stay within the range shown.</p><div class="scroll"><table><tr><th>Key</th><th>Meaning</th><th>Config</th><th>Override</th><th>Effective</th><th>Range</th><th>Set</th><th>Reset</th></tr>"#,
    );
    for r in rows {
        let Some(k) = LIMIT_KEYS.iter().find(|k| k.key == r.key) else {
            continue;
        };
        let effective = r.overridden.unwrap_or(r.config);
        let input = match k.kind {
            LimitKind::Switch => format!(
                r#"<select name="value"><option value="1"{}>true</option><option value="0"{}>false</option></select>"#,
                if effective != 0 { " selected" } else { "" },
                if effective == 0 { " selected" } else { "" }
            ),
            LimitKind::Number => format!(
                r#"<input name="value" type="number" required min="{}" max="{}" value="{effective}" size="8">"#,
                k.min, k.max
            ),
        };
        let range = match k.kind {
            LimitKind::Switch => "true / false".to_string(),
            LimitKind::Number => format!("{} to {}", k.min, k.max),
        };
        let reset = if r.overridden.is_some() {
            action_form("/admin/limits/reset", csrf, &hidden("key", k.key), "Reset")
        } else {
            "-".into()
        };
        let _ = write!(
            b,
            r#"<tr><td><code>{}</code></td><td>{}</td><td class="num">{}</td><td class="num">{}</td><td class="num"><b>{}</b></td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
            esc(k.key),
            esc(k.help),
            esc(&limit_value(k.kind, r.config)),
            r.overridden
                .map_or("-".into(), |v| esc(&limit_value(k.kind, v))),
            esc(&limit_value(k.kind, effective)),
            esc(&range),
            action_form(
                "/admin/limits/set",
                csrf,
                &format!("{}{input}", hidden("key", k.key)),
                "Set"
            ),
            reset
        );
    }
    b += "</table></div>";
    b
}

pub fn audit(now: u64, rows: &[AuditRow]) -> String {
    let mut b = format!(
        r#"<p>Every panel action, including refused step-up codes; newest first, last {}. The panel cannot edit or delete these rows.</p>"#,
        super::queries::MAX_AUDIT_ROWS
    );
    if rows.is_empty() {
        b += r#"<p class="muted">No actions yet.</p>"#;
        return b;
    }
    b += r#"<div class="scroll"><table><tr><th>Time</th><th>Actor</th><th>Network</th><th>Action</th><th>Target</th><th>Detail</th><th>Outcome</th></tr>"#;
    for r in rows {
        let _ = write!(
            b,
            r#"<tr><td title="{}">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
            fmt_ts(r.ts),
            esc(&ago(now, Some(r.ts))),
            esc(&r.actor),
            opt(&r.ip_prefix),
            esc(&r.action),
            opt(&r.target),
            opt(&r.detail),
            esc(&r.outcome)
        );
    }
    b += "</table></div>";
    b
}

pub const STYLE_CSS: &str = include_str!("style.css");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping() {
        assert_eq!(
            esc(r#"<a href="x">'&'</a>"#),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
        assert_eq!(qv("a b/c"), "a%20b%2Fc");
    }

    #[test]
    fn chart_renders_every_point() {
        let s = Series {
            names: vec!["a", "b"],
            points: vec![
                ("2026-11-08".into(), vec![1, 2]),
                ("2026-11-09".into(), vec![0, 0]),
            ],
        };
        let svg = bar_chart(&s, day_label);
        assert_eq!(svg.matches("<title>").count(), 2);
        assert!(svg.contains("11-09"));
        assert!(!svg.contains("style="), "CSP: no inline styles");
    }
}
