//! Server-rendered admin pages: plain HTML, one external stylesheet, inline
//! SVG charts, no JavaScript. Every dynamic value goes through [`esc`].

use std::fmt::Write as _;

use super::queries::{
    Count, EventRow, GroupDetail, GroupFilter, GroupRow, Overview, Pushes, Security, Series,
};

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
    b += r#"<div class="scroll"><table><tr><th>Group</th><th>Created</th><th>Last active</th><th>Macs</th><th>Phones</th><th>Licence</th><th>Country</th><th>Requests 30 d</th><th>Pushes 30 d</th></tr>"#;
    for g in rows {
        let lic = match (&g.tier, &g.environment) {
            (Some(t), Some(e)) => format!("{t} / {e}"),
            _ => "-".into(),
        };
        let _ = write!(
            b,
            r#"<tr><td><a href="/admin/groups/{}"><code>{}</code></a></td><td>{}</td><td>{}</td><td class="num">{}</td><td class="num">{}</td><td>{}</td><td>{}</td><td class="num">{}</td><td class="num">{}</td></tr>"#,
            qv(&g.group_id),
            esc(&g.group_id),
            fmt_date(g.created_at),
            esc(&ago(now, g.last_active)),
            g.macs,
            g.phones,
            esc(&lic),
            opt(&g.country),
            g.requests_30d,
            g.pushes_30d
        );
    }
    b.push_str("</table></div>");
    b
}

pub fn group_detail(now: u64, g: &GroupDetail) -> String {
    let mut b = format!(
        r#"<p><code>{}</code> · created {} · mailbox {} messages · {} queued commands</p>"#,
        esc(&g.group_id),
        fmt_ts(g.created_at),
        g.mailbox_messages,
        g.queued_commands
    );
    b += "<h2>Licence</h2>";
    match &g.licence {
        Some(l) => {
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
        "<div class=\"card\">{}</div>",
        count_table("Licence verifications (30 d)", &s.licence_outcomes)
    );
    b += "</section><h2>Bans (30 d)</h2>";
    b += &events_table(now, &s.bans, true);
    b += "<h2>Admin logins</h2>";
    b += &events_table(now, &s.admin_logins, true);
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
