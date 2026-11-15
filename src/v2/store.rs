//! SQLite persistence for v2: groups, devices, the message mailbox and the
//! command queue. Blobs stored here are opaque ciphertext (see PROTOCOL.md).
//!
//! One connection behind a mutex; every call runs on the blocking pool so the
//! async workers never wait on disk.

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension};
use subtle::ConstantTimeEq;

use super::licence::VerifiedLicence;

pub const DB_FILE: &str = "metriccupid-push.sqlite3";
pub const MAX_DEVICES: usize = 10;
pub const MESSAGE_RETENTION_SECS: u64 = 24 * 3600;
pub const MAX_MESSAGES: usize = 500;
pub const COMMAND_RETENTION_SECS: u64 = 3600;
pub const MAX_COMMANDS: usize = 200;
/// Page size for `GET /v2/messages` and `GET /v2/commands`.
pub const PAGE: usize = 100;

/// Schema migrations, applied in order; `PRAGMA user_version` is the number
/// already applied. Never edit a released entry, append a new one.
const MIGRATIONS: &[&str] = &[
    r#"
CREATE TABLE groups (
    group_id     TEXT PRIMARY KEY,
    auth_key     BLOB NOT NULL,
    created_at   INTEGER NOT NULL,
    next_msg_seq INTEGER NOT NULL DEFAULT 0,
    next_cmd_seq INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

CREATE TABLE devices (
    group_id   TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    device_id  TEXT NOT NULL,
    kind       TEXT NOT NULL,
    name       TEXT NOT NULL,
    apns_token TEXT,
    apns_env   TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, device_id)
) WITHOUT ROWID;

CREATE TABLE messages (
    group_id    TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    msg_id      TEXT NOT NULL,
    type        TEXT NOT NULL,
    sealed      TEXT NOT NULL,
    urgency     TEXT NOT NULL,
    collapse_id TEXT,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (group_id, seq),
    UNIQUE (group_id, msg_id)
);
CREATE INDEX messages_created ON messages(created_at);

CREATE TABLE commands (
    group_id   TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    seq        INTEGER NOT NULL,
    cmd_id     TEXT NOT NULL,
    sealed     TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, seq),
    UNIQUE (group_id, cmd_id)
);
CREATE INDEX commands_created ON commands(created_at);
"#,
    r#"
ALTER TABLE devices ADD COLUMN last_seen INTEGER;
"#,
    r#"
CREATE TABLE activity_tokens (
    group_id   TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    kind       TEXT NOT NULL,
    push_token TEXT NOT NULL,
    apns_env   TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, device_id, kind),
    FOREIGN KEY (group_id, device_id) REFERENCES devices(group_id, device_id) ON DELETE CASCADE
) WITHOUT ROWID;
"#,
    // Licences (PROTOCOL.md section 13). `tier` is `founder` for every App
    // Store purchase today; subscriptions will add other tiers.
    r#"
CREATE TABLE group_licences (
    group_id                     TEXT PRIMARY KEY REFERENCES groups(group_id) ON DELETE CASCADE,
    kind                         TEXT NOT NULL,
    tier                         TEXT NOT NULL,
    environment                  TEXT NOT NULL,
    app_transaction_id           TEXT NOT NULL,
    original_purchase_date       INTEGER,
    original_application_version TEXT,
    original_platform            TEXT,
    attached_at                  INTEGER NOT NULL,
    verified_at                  INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX group_licences_purchase ON group_licences(app_transaction_id);
"#,
    // Admin panel metrics (src/metrics.rs): metadata only, no full IPs.
    r#"
CREATE TABLE events (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    group_id    TEXT,
    device_id   TEXT,
    route       TEXT,
    status      INTEGER,
    outcome     TEXT,
    detail      TEXT,
    latency_ms  INTEGER,
    duration_s  INTEGER,
    country     TEXT,
    ip_prefix   TEXT,
    app_version TEXT,
    apns_status INTEGER,
    apns_reason TEXT,
    bytes       INTEGER
);
CREATE INDEX events_ts ON events(ts);
CREATE INDEX events_kind_ts ON events(kind, ts);
CREATE INDEX events_group_ts ON events(group_id, ts);

CREATE TABLE daily_agg (
    day            TEXT NOT NULL,
    kind           TEXT NOT NULL,
    route          TEXT NOT NULL,
    status         INTEGER NOT NULL,
    outcome        TEXT NOT NULL,
    group_id       TEXT NOT NULL,
    country        TEXT NOT NULL,
    count          INTEGER NOT NULL,
    latency_ms_sum INTEGER NOT NULL,
    bytes_sum      INTEGER NOT NULL,
    PRIMARY KEY (day, kind, route, status, outcome, group_id, country)
) WITHOUT ROWID;
CREATE INDEX daily_agg_group ON daily_agg(group_id, day);

CREATE TABLE client_activity (
    group_id    TEXT NOT NULL,
    device_id   TEXT NOT NULL,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    app_version TEXT,
    country     TEXT,
    PRIMARY KEY (group_id, device_id)
) WITHOUT ROWID;
"#,
    // The newest snapshot per group (PROTOCOL.md section 6.6a): one row,
    // replaced on every post, never in the mailbox.
    r#"
CREATE TABLE snapshots (
    group_id   TEXT PRIMARY KEY REFERENCES groups(group_id) ON DELETE CASCADE,
    snap_id    TEXT NOT NULL,
    sealed     TEXT NOT NULL,
    created_at INTEGER NOT NULL
) WITHOUT ROWID;
"#,
];

/// Objects added after schema version 6 without a numbered migration, so
/// `user_version` stays 6 and a 0.2.0 binary (which refuses newer versions)
/// can still open the database after an image rollback; it ignores these
/// tables, and SQLite still applies their cascades. A later numbered
/// migration takes them over with `IF NOT EXISTS`. Only add idempotent
/// `IF NOT EXISTS` statements here.
const AUX_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS gateway_groups (
    group_id   TEXT PRIMARY KEY REFERENCES groups(group_id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    licensed   INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS gateway_tokens (
    token     TEXT PRIMARY KEY,
    group_id  TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    last_used INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS gateway_tokens_group ON gateway_tokens(group_id);
CREATE INDEX IF NOT EXISTS devices_apns_token ON devices(apns_token);
CREATE INDEX IF NOT EXISTS activity_tokens_push_token ON activity_tokens(push_token);
CREATE TABLE IF NOT EXISTS licence_attaches (
    app_transaction_id TEXT NOT NULL,
    attached_at        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS licence_attaches_purchase
    ON licence_attaches(app_transaction_id, attached_at);
-- Admin management (0.2.2, src/controls.rs). Written only by panel actions.
CREATE TABLE IF NOT EXISTS admin_audit (
    id        INTEGER PRIMARY KEY,
    ts        INTEGER NOT NULL,
    actor     TEXT NOT NULL,
    ip_prefix TEXT,
    action    TEXT NOT NULL,
    target    TEXT,
    detail    TEXT,
    outcome   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS admin_audit_ts ON admin_audit(ts);
CREATE TABLE IF NOT EXISTS manual_bans (
    net        TEXT PRIMARY KEY,
    until      INTEGER NOT NULL,
    reason     TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    actor      TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS group_suspensions (
    group_id     TEXT PRIMARY KEY REFERENCES groups(group_id) ON DELETE CASCADE,
    suspended_at INTEGER NOT NULL,
    reason       TEXT NOT NULL,
    actor        TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS revoked_licences (
    app_transaction_id TEXT PRIMARY KEY,
    revoked_at         INTEGER NOT NULL,
    reason             TEXT NOT NULL,
    actor              TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS limit_overrides (
    key        TEXT PRIMARY KEY,
    value      INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    actor      TEXT NOT NULL
) WITHOUT ROWID;
"#;

/// New attaches of one purchase to another group per 24 h.
pub const MAX_ATTACHES_PER_DAY: i64 = 3;
pub const ATTACH_WINDOW_SECS: u64 = 24 * 3600;
/// A gateway token binding unused for longer than this may move to another
/// gateway group (phones send a heartbeat every 15 min).
pub const GATEWAY_BINDING_IDLE_SECS: u64 = 24 * 3600;
/// `gateway_tokens.last_used` is written at most this often.
pub const GATEWAY_TOUCH_SECS: u64 = 600;
/// Bindings unused this long are deleted by [`cleanup`].
pub const GATEWAY_BINDING_RETENTION_SECS: u64 = 7 * 24 * 3600;

#[derive(Debug)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError(e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub device_id: String,
    pub kind: String,
    pub name: String,
    pub apns_token: Option<String>,
    pub apns_env: String,
    pub created_at: u64,
    pub updated_at: u64,
    /// Macs: last time the server heard from its stream (Unix seconds).
    pub last_seen: Option<u64>,
}

/// A Live Activity push token of a phone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityToken {
    pub device_id: String,
    /// `update` (one running activity) or `start` (push-to-start).
    pub kind: String,
    pub push_token: String,
    pub apns_env: String,
    /// When the activity started (`update`) or the token was registered (`start`).
    pub started_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub cursor: u64,
    pub id: String,
    pub kind: String,
    pub sealed: String,
    pub urgency: String,
    pub collapse_id: Option<String>,
    pub received_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCommand {
    pub cursor: u64,
    pub id: String,
    pub sealed: String,
    pub received_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateGroup {
    Created,
    /// Same id and same key: idempotent retry.
    Exists,
    /// Same id, different key.
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upsert {
    Created,
    Updated,
    LimitReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insert {
    Stored(u64),
    Duplicate(u64),
    Full,
}

/// The licence attached to a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupLicence {
    pub kind: String,
    pub tier: String,
    pub environment: String,
    pub app_transaction_id: String,
    pub verified_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attach {
    /// First licence of the group, or another purchase than before.
    Attached,
    /// The same purchase again: `verified_at` and details updated.
    Refreshed,
    /// The purchase is already attached to `max` other groups.
    InUse,
}

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
    path: std::path::PathBuf,
}

impl Store {
    /// Open (or create) the database in `dir` and apply migrations.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        let path = dir.join(DB_FILE);
        let mut conn = Connection::open(&path)
            .map_err(|e| StoreError(format!("cannot open {}: {e}", path.display())))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // The root filesystem is read-only in the container: no temp files.
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        migrate(&mut conn)?;
        ensure_aux_schema(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            path,
        })
    }

    /// The database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A second, read-only connection to the same database (WAL lets it
    /// read while the main connection writes). Used by the admin panel so
    /// its queries never hold the API's connection.
    pub fn open_reader(&self) -> Result<Self, StoreError> {
        use rusqlite::OpenFlags;
        let conn = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            path: self.path.clone(),
        })
    }

    /// Run `f` with the connection on the calling thread. For startup only
    /// (loading the admin controls before the server accepts requests).
    pub fn blocking<R>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let mut c = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut c)
    }

    /// Run `f` with the connection on the blocking thread pool.
    pub async fn call<R, F>(&self, f: F) -> Result<R, StoreError>
    where
        R: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<R, StoreError> + Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut c = conn.lock().unwrap_or_else(|e| e.into_inner());
            f(&mut c)
        })
        .await
        .map_err(|e| StoreError(format!("storage task failed: {e}")))?
    }
}

fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let applied: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let applied = usize::try_from(applied).unwrap_or(usize::MAX);
    if applied > MIGRATIONS.len() {
        return Err(StoreError(format!(
            "database schema version {applied} is newer than this binary supports ({}); refusing to downgrade",
            MIGRATIONS.len()
        )));
    }
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(applied) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", (i + 1) as i64)?;
        tx.commit()?;
    }
    Ok(())
}

/// Create the [`AUX_SCHEMA`] objects; leaves `user_version` unchanged.
pub fn ensure_aux_schema(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(AUX_SCHEMA)?;
    Ok(())
}

fn ts(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

pub fn create_group(
    c: &mut Connection,
    group_id: &str,
    auth_key: &[u8; 32],
    now: u64,
) -> Result<CreateGroup, StoreError> {
    create_group_in(c, group_id, auth_key, now)
}

fn create_group_in(
    c: &Connection,
    group_id: &str,
    auth_key: &[u8; 32],
    now: u64,
) -> Result<CreateGroup, StoreError> {
    let existing: Option<Vec<u8>> = c
        .query_row(
            "SELECT auth_key FROM groups WHERE group_id = ?1",
            [group_id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(k) = existing {
        return Ok(if bool::from(k.as_slice().ct_eq(auth_key)) {
            CreateGroup::Exists
        } else {
            CreateGroup::Conflict
        });
    }
    c.execute(
        "INSERT INTO groups (group_id, auth_key, created_at) VALUES (?1, ?2, ?3)",
        params![group_id, auth_key.as_slice(), now as i64],
    )?;
    Ok(CreateGroup::Created)
}

/// Delete a group and everything it owns (devices, mailbox, queue, tokens,
/// licence). Returns whether it existed.
pub fn delete_group(c: &mut Connection, group_id: &str) -> Result<bool, StoreError> {
    Ok(c.execute("DELETE FROM groups WHERE group_id = ?1", [group_id])? > 0)
}

pub fn group_licence(
    c: &mut Connection,
    group_id: &str,
) -> Result<Option<GroupLicence>, StoreError> {
    Ok(c.query_row(
        "SELECT kind, tier, environment, app_transaction_id, verified_at
         FROM group_licences WHERE group_id = ?1",
        [group_id],
        |r| {
            Ok(GroupLicence {
                kind: r.get(0)?,
                tier: r.get(1)?,
                environment: r.get(2)?,
                app_transaction_id: r.get(3)?,
                verified_at: ts(r.get(4)?),
            })
        },
    )
    .optional()?)
}

/// Attach (or refresh) `lic` on an existing group, unless that purchase is
/// already attached to `max_groups` other groups.
pub fn attach_licence(
    c: &mut Connection,
    group_id: &str,
    lic: &VerifiedLicence,
    max_groups: u32,
    now: u64,
) -> Result<Attach, StoreError> {
    let tx = c.transaction()?;
    let r = attach_in(&tx, group_id, lic, max_groups, now)?;
    tx.commit()?;
    Ok(r)
}

/// `create_group` and `attach_licence` in one transaction: a group refused
/// with `InUse` is not created.
pub fn create_group_with_licence(
    c: &mut Connection,
    group_id: &str,
    auth_key: &[u8; 32],
    lic: &VerifiedLicence,
    max_groups: u32,
    now: u64,
) -> Result<(CreateGroup, Attach), StoreError> {
    let tx = c.transaction()?;
    let created = create_group_in(&tx, group_id, auth_key, now)?;
    if created == CreateGroup::Conflict {
        return Ok((created, Attach::InUse));
    }
    let attach = attach_in(&tx, group_id, lic, max_groups, now)?;
    if attach == Attach::InUse {
        // Dropping the transaction rolls the new group back.
        return Ok((created, attach));
    }
    tx.commit()?;
    Ok((created, attach))
}

fn attach_in(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    lic: &VerifiedLicence,
    max_groups: u32,
    now: u64,
) -> Result<Attach, StoreError> {
    let current: Option<String> = tx
        .query_row(
            "SELECT app_transaction_id FROM group_licences WHERE group_id = ?1",
            [group_id],
            |r| r.get(0),
        )
        .optional()?;
    let same = current.as_deref() == Some(lic.app_transaction_id.as_str());
    if !same {
        let others: i64 = tx.query_row(
            "SELECT COUNT(*) FROM group_licences WHERE app_transaction_id = ?1 AND group_id != ?2",
            [&lic.app_transaction_id, group_id],
            |r| r.get(0),
        )?;
        if others >= i64::from(max_groups) {
            return Ok(Attach::InUse);
        }
        let recent: i64 = tx.query_row(
            "SELECT COUNT(*) FROM licence_attaches WHERE app_transaction_id = ?1 AND attached_at > ?2",
            params![lic.app_transaction_id, cutoff(now, ATTACH_WINDOW_SECS)],
            |r| r.get(0),
        )?;
        if recent >= MAX_ATTACHES_PER_DAY {
            return Ok(Attach::InUse);
        }
        tx.execute(
            "INSERT INTO licence_attaches (app_transaction_id, attached_at) VALUES (?1, ?2)",
            params![lic.app_transaction_id, now as i64],
        )?;
    }
    tx.execute(
        "INSERT INTO group_licences (group_id, kind, tier, environment, app_transaction_id,
             original_purchase_date, original_application_version, original_platform,
             attached_at, verified_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
         ON CONFLICT (group_id) DO UPDATE SET kind = ?2, tier = ?3, environment = ?4,
             app_transaction_id = ?5, original_purchase_date = ?6,
             original_application_version = ?7, original_platform = ?8,
             attached_at = CASE WHEN app_transaction_id = ?5 THEN attached_at ELSE ?9 END,
             verified_at = ?9",
        params![
            group_id,
            lic.kind,
            lic.tier,
            lic.environment,
            lic.app_transaction_id,
            lic.original_purchase_date
                .map(|d| d.min(i64::MAX as u64) as i64),
            lic.original_application_version,
            lic.original_platform,
            now as i64
        ],
    )?;
    Ok(if same {
        Attach::Refreshed
    } else {
        Attach::Attached
    })
}

pub fn group_key(c: &mut Connection, group_id: &str) -> Result<Option<[u8; 32]>, StoreError> {
    let k: Option<Vec<u8>> = c
        .query_row(
            "SELECT auth_key FROM groups WHERE group_id = ?1",
            [group_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(k.and_then(|k| k.try_into().ok()))
}

fn row_device(r: &rusqlite::Row<'_>) -> rusqlite::Result<Device> {
    Ok(Device {
        device_id: r.get(0)?,
        kind: r.get(1)?,
        name: r.get(2)?,
        apns_token: r.get(3)?,
        apns_env: r.get(4)?,
        created_at: ts(r.get(5)?),
        updated_at: ts(r.get(6)?),
        last_seen: r.get::<_, Option<i64>>(7)?.map(ts),
    })
}

const DEVICE_COLS: &str =
    "device_id, kind, name, apns_token, apns_env, created_at, updated_at, last_seen";

pub fn device(
    c: &mut Connection,
    group_id: &str,
    device_id: &str,
) -> Result<Option<Device>, StoreError> {
    Ok(c.query_row(
        &format!("SELECT {DEVICE_COLS} FROM devices WHERE group_id = ?1 AND device_id = ?2"),
        [group_id, device_id],
        row_device,
    )
    .optional()?)
}

pub fn list_devices(c: &mut Connection, group_id: &str) -> Result<Vec<Device>, StoreError> {
    let mut st = c.prepare(&format!(
        "SELECT {DEVICE_COLS} FROM devices WHERE group_id = ?1 ORDER BY created_at, device_id"
    ))?;
    let rows = st.query_map([group_id], row_device)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub fn upsert_device(
    c: &mut Connection,
    group_id: &str,
    d: &Device,
    now: u64,
) -> Result<Upsert, StoreError> {
    let tx = c.transaction()?;
    let exists: bool = tx
        .query_row(
            "SELECT 1 FROM devices WHERE group_id = ?1 AND device_id = ?2",
            [group_id, &d.device_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let result = if exists {
        tx.execute(
            "UPDATE devices SET kind = ?3, name = ?4, apns_token = ?5, apns_env = ?6, updated_at = ?7
             WHERE group_id = ?1 AND device_id = ?2",
            params![group_id, d.device_id, d.kind, d.name, d.apns_token, d.apns_env, now as i64],
        )?;
        Upsert::Updated
    } else {
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM devices WHERE group_id = ?1",
            [group_id],
            |r| r.get(0),
        )?;
        if count as usize >= MAX_DEVICES {
            return Ok(Upsert::LimitReached);
        }
        tx.execute(
            "INSERT INTO devices (group_id, device_id, kind, name, apns_token, apns_env, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            params![group_id, d.device_id, d.kind, d.name, d.apns_token, d.apns_env, now as i64],
        )?;
        Upsert::Created
    };
    tx.commit()?;
    Ok(result)
}

pub fn delete_device(
    c: &mut Connection,
    group_id: &str,
    device_id: &str,
) -> Result<bool, StoreError> {
    Ok(c.execute(
        "DELETE FROM devices WHERE group_id = ?1 AND device_id = ?2",
        [group_id, device_id],
    )? > 0)
}

/// Record that the server heard from the device's stream at `now`.
pub fn touch_device(
    c: &mut Connection,
    group_id: &str,
    device_id: &str,
    now: u64,
) -> Result<(), StoreError> {
    c.execute(
        "UPDATE devices SET last_seen = ?3 WHERE group_id = ?1 AND device_id = ?2",
        params![group_id, device_id, now as i64],
    )?;
    Ok(())
}

/// iOS devices with an APNs token.
pub fn push_targets(c: &mut Connection, group_id: &str) -> Result<Vec<Device>, StoreError> {
    let mut st = c.prepare(&format!(
        "SELECT {DEVICE_COLS} FROM devices
         WHERE group_id = ?1 AND kind = 'ios' AND apns_token IS NOT NULL
         ORDER BY device_id"
    ))?;
    let rows = st.query_map([group_id], row_device)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Forget a token APNs reported as invalid, unless the device has already
/// registered a new one in the meantime.
pub fn clear_token(
    c: &mut Connection,
    group_id: &str,
    device_id: &str,
    token: &str,
) -> Result<bool, StoreError> {
    Ok(c.execute(
        "UPDATE devices SET apns_token = NULL
         WHERE group_id = ?1 AND device_id = ?2 AND apns_token = ?3",
        [group_id, device_id, token],
    )? > 0)
}

pub struct NewMessage {
    pub id: String,
    pub kind: String,
    pub sealed: String,
    pub urgency: String,
    pub collapse_id: Option<String>,
}

fn next_seq(tx: &rusqlite::Transaction<'_>, group_id: &str, col: &str) -> Result<u64, StoreError> {
    let seq: i64 = tx.query_row(
        &format!("UPDATE groups SET {col} = {col} + 1 WHERE group_id = ?1 RETURNING {col}"),
        [group_id],
        |r| r.get(0),
    )?;
    Ok(ts(seq))
}

/// Store a message; the mailbox keeps the newest [`MAX_MESSAGES`] per group.
pub fn insert_message(
    c: &mut Connection,
    group_id: &str,
    m: &NewMessage,
    now: u64,
) -> Result<Insert, StoreError> {
    let tx = c.transaction()?;
    let dup: Option<i64> = tx
        .query_row(
            "SELECT seq FROM messages WHERE group_id = ?1 AND msg_id = ?2 AND created_at > ?3",
            params![group_id, m.id, cutoff(now, MESSAGE_RETENTION_SECS)],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(seq) = dup {
        return Ok(Insert::Duplicate(ts(seq)));
    }
    // An expired row with the same id may still be waiting for cleanup.
    tx.execute(
        "DELETE FROM messages WHERE group_id = ?1 AND msg_id = ?2",
        [group_id, &m.id],
    )?;
    // Only the newest summary matters: older ones would push alerts out of
    // the mailbox.
    if m.kind == "summary" {
        tx.execute(
            "DELETE FROM messages WHERE group_id = ?1 AND type = 'summary'",
            [group_id],
        )?;
    }
    let seq = next_seq(&tx, group_id, "next_msg_seq")?;
    tx.execute(
        "INSERT INTO messages (group_id, seq, msg_id, type, sealed, urgency, collapse_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![group_id, seq as i64, m.id, m.kind, m.sealed, m.urgency, m.collapse_id, now as i64],
    )?;
    tx.execute(
        "DELETE FROM messages WHERE group_id = ?1 AND seq <= ?2",
        params![group_id, seq as i64 - MAX_MESSAGES as i64],
    )?;
    tx.commit()?;
    Ok(Insert::Stored(seq))
}

fn cutoff(now: u64, retention: u64) -> i64 {
    now.saturating_sub(retention) as i64
}

/// Messages with `cursor > since`, oldest first, plus whether more exist.
pub fn messages_since(
    c: &mut Connection,
    group_id: &str,
    since: u64,
    now: u64,
) -> Result<(Vec<StoredMessage>, bool), StoreError> {
    let mut st = c.prepare(
        "SELECT seq, msg_id, type, sealed, urgency, collapse_id, created_at FROM messages
         WHERE group_id = ?1 AND seq > ?2 AND created_at > ?3 ORDER BY seq LIMIT ?4",
    )?;
    let mut rows: Vec<StoredMessage> = st
        .query_map(
            params![
                group_id,
                since.min(i64::MAX as u64) as i64,
                cutoff(now, MESSAGE_RETENTION_SECS),
                (PAGE + 1) as i64
            ],
            |r| {
                Ok(StoredMessage {
                    cursor: ts(r.get(0)?),
                    id: r.get(1)?,
                    kind: r.get(2)?,
                    sealed: r.get(3)?,
                    urgency: r.get(4)?,
                    collapse_id: r.get(5)?,
                    received_at: ts(r.get(6)?),
                })
            },
        )?
        .collect::<Result<_, _>>()?;
    let more = rows.len() > PAGE;
    rows.truncate(PAGE);
    Ok((rows, more))
}

pub fn insert_command(
    c: &mut Connection,
    group_id: &str,
    id: &str,
    sealed: &str,
    now: u64,
) -> Result<Insert, StoreError> {
    let tx = c.transaction()?;
    let live = cutoff(now, COMMAND_RETENTION_SECS);
    let dup: Option<i64> = tx
        .query_row(
            "SELECT seq FROM commands WHERE group_id = ?1 AND cmd_id = ?2 AND created_at > ?3",
            params![group_id, id, live],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(seq) = dup {
        return Ok(Insert::Duplicate(ts(seq)));
    }
    let count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM commands WHERE group_id = ?1 AND created_at > ?2",
        params![group_id, live],
        |r| r.get(0),
    )?;
    if count as usize >= MAX_COMMANDS {
        return Ok(Insert::Full);
    }
    tx.execute(
        "DELETE FROM commands WHERE group_id = ?1 AND cmd_id = ?2",
        [group_id, id],
    )?;
    let seq = next_seq(&tx, group_id, "next_cmd_seq")?;
    tx.execute(
        "INSERT INTO commands (group_id, seq, cmd_id, sealed, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![group_id, seq as i64, id, sealed, now as i64],
    )?;
    tx.commit()?;
    Ok(Insert::Stored(seq))
}

pub fn commands_since(
    c: &mut Connection,
    group_id: &str,
    since: u64,
    now: u64,
    limit: usize,
) -> Result<(Vec<StoredCommand>, bool), StoreError> {
    let mut st = c.prepare(
        "SELECT seq, cmd_id, sealed, created_at FROM commands
         WHERE group_id = ?1 AND seq > ?2 AND created_at > ?3 ORDER BY seq LIMIT ?4",
    )?;
    let mut rows: Vec<StoredCommand> = st
        .query_map(
            params![
                group_id,
                since.min(i64::MAX as u64) as i64,
                cutoff(now, COMMAND_RETENTION_SECS),
                (limit + 1) as i64
            ],
            |r| {
                Ok(StoredCommand {
                    cursor: ts(r.get(0)?),
                    id: r.get(1)?,
                    sealed: r.get(2)?,
                    received_at: ts(r.get(3)?),
                })
            },
        )?
        .collect::<Result<_, _>>()?;
    let more = rows.len() > limit;
    rows.truncate(limit);
    Ok((rows, more))
}

pub fn ack_command(c: &mut Connection, group_id: &str, cursor: u64) -> Result<bool, StoreError> {
    Ok(c.execute(
        "DELETE FROM commands WHERE group_id = ?1 AND seq = ?2",
        params![group_id, cursor.min(i64::MAX as u64) as i64],
    )? > 0)
}

/// Register or replace a phone's activity token (`kind` = `update` or `start`).
/// Returns true if it was new.
#[allow(clippy::too_many_arguments)]
pub fn put_activity_token(
    c: &mut Connection,
    group_id: &str,
    device_id: &str,
    kind: &str,
    token: &str,
    env: &str,
    started_at: u64,
    now: u64,
) -> Result<bool, StoreError> {
    let n = c.execute(
        "INSERT INTO activity_tokens (group_id, device_id, kind, push_token, apns_env, started_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT (group_id, device_id, kind) DO NOTHING",
        params![group_id, device_id, kind, token, env, started_at as i64, now as i64],
    )?;
    if n == 0 {
        c.execute(
            "UPDATE activity_tokens SET push_token = ?4, apns_env = ?5, started_at = ?6, updated_at = ?7
             WHERE group_id = ?1 AND device_id = ?2 AND kind = ?3",
            params![group_id, device_id, kind, token, env, started_at as i64, now as i64],
        )?;
    }
    Ok(n > 0)
}

pub fn delete_activity_token(
    c: &mut Connection,
    group_id: &str,
    device_id: &str,
    kind: &str,
) -> Result<bool, StoreError> {
    Ok(c.execute(
        "DELETE FROM activity_tokens WHERE group_id = ?1 AND device_id = ?2 AND kind = ?3",
        [group_id, device_id, kind],
    )? > 0)
}

/// Forget a token APNs refused, unless it was replaced meanwhile.
pub fn clear_activity_token(
    c: &mut Connection,
    group_id: &str,
    device_id: &str,
    kind: &str,
    token: &str,
) -> Result<bool, StoreError> {
    Ok(c.execute(
        "DELETE FROM activity_tokens WHERE group_id = ?1 AND device_id = ?2 AND kind = ?3 AND push_token = ?4",
        [group_id, device_id, kind, token],
    )? > 0)
}

/// Drop every `update` token of the group (after an `end`), or only those
/// whose activity started at or before `started_before` (ended by iOS).
pub fn delete_update_tokens(
    c: &mut Connection,
    group_id: &str,
    started_before: Option<u64>,
) -> Result<usize, StoreError> {
    let cut = started_before.map_or(i64::MAX, |t| t.min(i64::MAX as u64) as i64);
    Ok(c.execute(
        "DELETE FROM activity_tokens WHERE group_id = ?1 AND kind = 'update' AND started_at <= ?2",
        params![group_id, cut],
    )?)
}

/// Activity tokens of the group's phones.
pub fn activity_tokens(
    c: &mut Connection,
    group_id: &str,
) -> Result<Vec<ActivityToken>, StoreError> {
    let mut st = c.prepare(
        "SELECT a.device_id, a.kind, a.push_token, a.apns_env, a.started_at
         FROM activity_tokens a JOIN devices d ON d.group_id = a.group_id AND d.device_id = a.device_id
         WHERE a.group_id = ?1 AND d.kind = 'ios' ORDER BY a.device_id, a.kind",
    )?;
    let rows = st.query_map([group_id], |r| {
        Ok(ActivityToken {
            device_id: r.get(0)?,
            kind: r.get(1)?,
            push_token: r.get(2)?,
            apns_env: r.get(3)?,
            started_at: ts(r.get(4)?),
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// The stored snapshot of a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub id: String,
    pub sealed: String,
    pub received_at: u64,
}

/// Replace the group's snapshot. `false` if the stored one already has `id`
/// (a retry): nothing changes.
pub fn put_snapshot(
    c: &mut Connection,
    group_id: &str,
    id: &str,
    sealed: &str,
    now: u64,
) -> Result<bool, StoreError> {
    let tx = c.transaction()?;
    let same: Option<String> = tx
        .query_row(
            "SELECT snap_id FROM snapshots WHERE group_id = ?1",
            [group_id],
            |r| r.get(0),
        )
        .optional()?;
    if same.as_deref() == Some(id) {
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO snapshots (group_id, snap_id, sealed, created_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(group_id) DO UPDATE SET snap_id = ?2, sealed = ?3, created_at = ?4",
        params![group_id, id, sealed, now as i64],
    )?;
    tx.commit()?;
    Ok(true)
}

/// The group's snapshot if it is younger than the mailbox retention.
pub fn snapshot(
    c: &mut Connection,
    group_id: &str,
    now: u64,
) -> Result<Option<Snapshot>, StoreError> {
    Ok(c.query_row(
        "SELECT snap_id, sealed, created_at FROM snapshots
         WHERE group_id = ?1 AND created_at > ?2",
        params![group_id, cutoff(now, MESSAGE_RETENTION_SECS)],
        |r| {
            Ok(Snapshot {
                id: r.get(0)?,
                sealed: r.get(1)?,
                received_at: ts(r.get(2)?),
            })
        },
    )
    .optional()?)
}

// --------------------------------------------------------------- gateway ---

/// Whether `group_id` is a gateway group, and if so whether it is licensed.
pub fn gateway_member(c: &mut Connection, group_id: &str) -> Result<Option<bool>, StoreError> {
    Ok(c.query_row(
        "SELECT licensed FROM gateway_groups WHERE group_id = ?1",
        [group_id],
        |r| r.get::<_, i64>(0),
    )
    .optional()?
    .map(|l| l != 0))
}

/// Like [`gateway_member`], plus the purchase id of the group's licence
/// (to honour revocations made after the group registered).
pub fn gateway_member_licence(
    c: &mut Connection,
    group_id: &str,
) -> Result<Option<(bool, Option<String>)>, StoreError> {
    Ok(c.query_row(
        "SELECT g.licensed, l.app_transaction_id FROM gateway_groups g
         LEFT JOIN group_licences l ON l.group_id = g.group_id WHERE g.group_id = ?1",
        [group_id],
        |r| Ok((r.get::<_, i64>(0)? != 0, r.get(1)?)),
    )
    .optional()?)
}

/// `group_id` is already a gateway group, or there are fewer than `max`.
pub fn gateway_has_room(c: &Connection, group_id: &str, max: u32) -> Result<bool, StoreError> {
    let member = c
        .query_row(
            "SELECT 1 FROM gateway_groups WHERE group_id = ?1",
            [group_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if member {
        return Ok(true);
    }
    let n: i64 = c.query_row("SELECT COUNT(*) FROM gateway_groups", [], |r| r.get(0))?;
    Ok(n < i64::from(max))
}

/// Make `group_id` (which must exist) a gateway group; `licensed` reflects
/// the latest registration.
pub fn put_gateway_group(
    c: &Connection,
    group_id: &str,
    licensed: bool,
    now: u64,
) -> Result<(), StoreError> {
    c.execute(
        "INSERT INTO gateway_groups (group_id, created_at, licensed) VALUES (?1, ?2, ?3)
         ON CONFLICT (group_id) DO UPDATE SET licensed = ?3",
        params![group_id, now as i64, i64::from(licensed)],
    )?;
    Ok(())
}

/// `token` is a device or Live Activity token of a hosted group other
/// than `group_id`.
pub fn token_owned_by_hosted(
    c: &Connection,
    token: &str,
    group_id: &str,
) -> Result<bool, StoreError> {
    Ok(c.query_row(
        "SELECT 1 FROM devices WHERE apns_token = ?1 AND group_id != ?2
         UNION ALL
         SELECT 1 FROM activity_tokens WHERE push_token = ?1 AND group_id != ?2
         LIMIT 1",
        [token, group_id],
        |_| Ok(()),
    )
    .optional()?
    .is_some())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bind {
    /// The token is (now) bound to the caller.
    Bound,
    /// A hosted user's token, or bound to another active gateway group.
    TakenElsewhere,
    /// The group already has its maximum of distinct tokens.
    TokenLimit,
    /// The group used up its re-bindings for today.
    RebindLimit,
}

/// Bind `token` to gateway group `group_id` (one transaction): refused if a
/// hosted group owns it or another gateway group used it within
/// [`GATEWAY_BINDING_IDLE_SECS`]; an idle binding moves when `rebind()`
/// allows it (rate limit); a new token needs room under `max_tokens`.
pub fn bind_gateway_token(
    c: &mut Connection,
    group_id: &str,
    token: &str,
    now: u64,
    max_tokens: u32,
    rebind: impl FnOnce() -> bool,
) -> Result<Bind, StoreError> {
    let tx = c.transaction()?;
    if token_owned_by_hosted(&tx, token, group_id)? {
        return Ok(Bind::TakenElsewhere);
    }
    let current: Option<(String, i64)> = tx
        .query_row(
            "SELECT group_id, last_used FROM gateway_tokens WHERE token = ?1",
            [token],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match current {
        Some((g, last)) if g == group_id => {
            if now.saturating_sub(ts(last)) >= GATEWAY_TOUCH_SECS {
                tx.execute(
                    "UPDATE gateway_tokens SET last_used = ?2 WHERE token = ?1",
                    params![token, now as i64],
                )?;
            }
        }
        other => {
            if let Some((_, last)) = &other {
                if now.saturating_sub(ts(*last)) <= GATEWAY_BINDING_IDLE_SECS {
                    return Ok(Bind::TakenElsewhere);
                }
            }
            // The group's own idle bindings no longer count toward its cap
            // (Live Activity tokens change with every activity).
            tx.execute(
                "DELETE FROM gateway_tokens WHERE group_id = ?1 AND last_used < ?2",
                params![group_id, cutoff(now, GATEWAY_BINDING_IDLE_SECS)],
            )?;
            let n: i64 = tx.query_row(
                "SELECT COUNT(*) FROM gateway_tokens WHERE group_id = ?1",
                [group_id],
                |r| r.get(0),
            )?;
            if n >= i64::from(max_tokens) {
                return Ok(Bind::TokenLimit);
            }
            if other.is_some() && !rebind() {
                return Ok(Bind::RebindLimit);
            }
            tx.execute(
                "INSERT INTO gateway_tokens (token, group_id, last_used) VALUES (?1, ?2, ?3)
                 ON CONFLICT (token) DO UPDATE SET group_id = ?2, last_used = ?3",
                params![token, group_id, now as i64],
            )?;
        }
    }
    tx.commit()?;
    Ok(Bind::Bound)
}

/// Forget a binding (APNs said the token is gone).
pub fn unbind_gateway_token(
    c: &mut Connection,
    group_id: &str,
    token: &str,
) -> Result<(), StoreError> {
    c.execute(
        "DELETE FROM gateway_tokens WHERE token = ?1 AND group_id = ?2",
        [token, group_id],
    )?;
    Ok(())
}

/// Delete expired messages, commands and snapshots; returns (messages,
/// commands) removed.
pub fn cleanup(c: &mut Connection, now: u64) -> Result<(usize, usize), StoreError> {
    let m = c.execute(
        "DELETE FROM messages WHERE created_at <= ?1",
        [cutoff(now, MESSAGE_RETENTION_SECS)],
    )?;
    c.execute(
        "DELETE FROM snapshots WHERE created_at <= ?1",
        [cutoff(now, MESSAGE_RETENTION_SECS)],
    )?;
    let k = c.execute(
        "DELETE FROM commands WHERE created_at <= ?1",
        [cutoff(now, COMMAND_RETENTION_SECS)],
    )?;
    c.execute(
        "DELETE FROM licence_attaches WHERE attached_at <= ?1",
        [cutoff(now, ATTACH_WINDOW_SECS)],
    )?;
    c.execute(
        "DELETE FROM gateway_tokens WHERE last_used <= ?1",
        [cutoff(now, GATEWAY_BINDING_RETENTION_SECS)],
    )?;
    c.execute("DELETE FROM manual_bans WHERE until <= ?1", [now as i64])?;
    Ok((m, k))
}

/// Row counts (messages, commands) for one group, including expired rows not
/// yet cleaned up. Used by tests and diagnostics.
pub fn counts(c: &mut Connection, group_id: &str) -> Result<(usize, usize), StoreError> {
    let m: i64 = c.query_row(
        "SELECT COUNT(*) FROM messages WHERE group_id = ?1",
        [group_id],
        |r| r.get(0),
    )?;
    let k: i64 = c.query_row(
        "SELECT COUNT(*) FROM commands WHERE group_id = ?1",
        [group_id],
        |r| r.get(0),
    )?;
    Ok((m as usize, k as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Connection::open(dir.path().join(DB_FILE)).unwrap();
        migrate(&mut c).unwrap();
        ensure_aux_schema(&c).unwrap();
        c.pragma_update(None, "foreign_keys", "ON").unwrap();
        (dir, c)
    }

    fn msg(id: &str) -> NewMessage {
        NewMessage {
            id: id.into(),
            kind: "alert".into(),
            sealed: "AAAA".into(),
            urgency: "normal".into(),
            collapse_id: None,
        }
    }

    #[test]
    fn migrations_are_idempotent_and_refuse_downgrade() {
        let (_d, mut c) = store();
        migrate(&mut c).unwrap();
        c.pragma_update(None, "user_version", 99).unwrap();
        assert!(migrate(&mut c).is_err());
    }

    #[test]
    fn aux_schema_keeps_user_version_and_0_2_0_can_still_open() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let path = store.path().to_path_buf();
        drop(store);
        let mut c = Connection::open(&path).unwrap();
        let v: i64 = c
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, 6);
        assert_eq!(v as usize, MIGRATIONS.len());
        // Idempotent.
        ensure_aux_schema(&c).unwrap();
        // What 0.2.0 runs on open: migrate only, which accepts version 6.
        migrate(&mut c).unwrap();
        c.pragma_update(None, "foreign_keys", "ON").unwrap();
        // 0.2.0's delete_group still works, and cascades into the new tables.
        create_group(&mut c, "g", &[1; 32], 0).unwrap();
        put_gateway_group(&c, "g", true, 0).unwrap();
        assert_eq!(
            bind_gateway_token(&mut c, "g", "t", 0, 30, || true).unwrap(),
            Bind::Bound
        );
        assert!(delete_group(&mut c, "g").unwrap());
        let n: i64 = c
            .query_row(
                "SELECT (SELECT COUNT(*) FROM gateway_groups) + (SELECT COUNT(*) FROM gateway_tokens)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0);
        // And Store::open again after that (0.2.1 after a roll-forward).
        drop(c);
        Store::open(dir.path()).unwrap();
    }

    #[test]
    fn gateway_membership_and_token_binding() {
        let (_d, mut c) = store();
        for g in ["a", "b", "h"] {
            create_group(&mut c, g, &[1; 32], 0).unwrap();
        }
        assert_eq!(gateway_member(&mut c, "a").unwrap(), None);
        assert!(gateway_has_room(&c, "a", 1).unwrap());
        put_gateway_group(&c, "a", false, 0).unwrap();
        assert_eq!(gateway_member(&mut c, "a").unwrap(), Some(false));
        assert!(gateway_has_room(&c, "a", 1).unwrap(), "members always fit");
        assert!(!gateway_has_room(&c, "b", 1).unwrap());
        put_gateway_group(&c, "a", true, 5).unwrap();
        assert_eq!(gateway_member(&mut c, "a").unwrap(), Some(true));
        put_gateway_group(&c, "b", false, 0).unwrap();

        // A hosted device's token is refused, even for an idle check later.
        let d = Device {
            device_id: "p".into(),
            kind: "ios".into(),
            name: "iPhone".into(),
            apns_token: Some("hosted".into()),
            apns_env: "production".into(),
            created_at: 0,
            updated_at: 0,
            last_seen: None,
        };
        upsert_device(&mut c, "h", &d, 0).unwrap();
        let bind = |c: &mut Connection, g: &str, t: &str, now: u64| {
            bind_gateway_token(c, g, t, now, 2, || true).unwrap()
        };
        assert_eq!(bind(&mut c, "a", "hosted", 0), Bind::TakenElsewhere);
        assert_eq!(bind(&mut c, "h", "hosted", 0), Bind::Bound, "own token");

        assert_eq!(bind(&mut c, "a", "t1", 0), Bind::Bound);
        assert_eq!(bind(&mut c, "b", "t1", 100), Bind::TakenElsewhere);
        // Used by "a" at 500 (within the touch interval: not written).
        assert_eq!(bind(&mut c, "a", "t1", 500), Bind::Bound);
        let idle = GATEWAY_BINDING_IDLE_SECS;
        assert_eq!(bind(&mut c, "b", "t1", idle), Bind::TakenElsewhere);
        assert_eq!(bind(&mut c, "b", "t1", idle + 1), Bind::Bound, "idle moves");
        assert_eq!(bind(&mut c, "a", "t1", idle + 2), Bind::TakenElsewhere);
        // Rebind limit is consulted only for a move.
        assert_eq!(
            bind_gateway_token(&mut c, "a", "t2", 0, 2, || false).unwrap(),
            Bind::Bound
        );
        assert_eq!(
            bind_gateway_token(&mut c, "b", "t2", 3 * idle, 2, || false).unwrap(),
            Bind::RebindLimit
        );
        // Token cap: "b" has t1, a second fits, the third does not.
        assert_eq!(bind(&mut c, "b", "t3", idle + 3), Bind::Bound);
        assert_eq!(bind(&mut c, "b", "t4", idle + 3), Bind::TokenLimit);
        unbind_gateway_token(&mut c, "b", "t3").unwrap();
        assert_eq!(bind(&mut c, "b", "t4", idle + 3), Bind::Bound);
        // At the cap, a binding idle for more than 24 h frees its slot.
        let later = 2 * idle + 4;
        assert_eq!(bind(&mut c, "b", "t4", later), Bind::Bound, "t4 in use");
        assert_eq!(bind(&mut c, "b", "t5", later), Bind::Bound, "t1 was idle");
        // Cleanup drops bindings unused for 7 days.
        cleanup(&mut c, later + GATEWAY_BINDING_RETENTION_SECS).unwrap();
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM gateway_tokens", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn one_purchase_attaches_at_most_three_new_groups_per_day() {
        let (_d, mut c) = store();
        let lic = VerifiedLicence {
            kind: "app_transaction",
            tier: "founder",
            environment: "production",
            app_transaction_id: "p".into(),
            original_purchase_date: None,
            original_application_version: None,
            original_platform: None,
            signed_date: 0,
        };
        let t = ATTACH_WINDOW_SECS * 10;
        for g in ["a", "b", "c", "d"] {
            create_group(&mut c, g, &[1; 32], 0).unwrap();
        }
        for g in ["a", "b", "c"] {
            assert_eq!(
                attach_licence(&mut c, g, &lic, 10, t).unwrap(),
                Attach::Attached
            );
        }
        assert_eq!(
            attach_licence(&mut c, "d", &lic, 10, t + 10).unwrap(),
            Attach::InUse
        );
        // Refreshing an attached group is not a new attach.
        assert_eq!(
            attach_licence(&mut c, "a", &lic, 10, t + 10).unwrap(),
            Attach::Refreshed
        );
        // Deleting a group does not give the attach back within 24 h.
        delete_group(&mut c, "a").unwrap();
        assert_eq!(
            attach_licence(&mut c, "d", &lic, 10, t + 20).unwrap(),
            Attach::InUse
        );
        let later = t + ATTACH_WINDOW_SECS + 1;
        cleanup(&mut c, later).unwrap();
        assert_eq!(
            attach_licence(&mut c, "d", &lic, 10, later).unwrap(),
            Attach::Attached
        );
    }

    #[test]
    fn snapshot_replace_dedup_expiry_and_cascade() {
        let (_d, mut c) = store();
        create_group(&mut c, "g", &[1; 32], 0).unwrap();
        assert_eq!(snapshot(&mut c, "g", 10).unwrap(), None);
        assert!(put_snapshot(&mut c, "g", "a", "AAAA", 10).unwrap());
        assert!(!put_snapshot(&mut c, "g", "a", "BBBB", 11).unwrap());
        assert!(put_snapshot(&mut c, "g", "b", "CCCC", 12).unwrap());
        let s = snapshot(&mut c, "g", 13).unwrap().unwrap();
        assert_eq!(
            (s.id.as_str(), s.sealed.as_str(), s.received_at),
            ("b", "CCCC", 12)
        );
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM snapshots", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        // Snapshots never show up in the mailbox.
        assert!(messages_since(&mut c, "g", 0, 13).unwrap().0.is_empty());
        let later = 12 + MESSAGE_RETENTION_SECS;
        assert_eq!(snapshot(&mut c, "g", later).unwrap(), None);
        cleanup(&mut c, later).unwrap();
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM snapshots", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
        put_snapshot(&mut c, "g", "c", "DDDD", later).unwrap();
        delete_group(&mut c, "g").unwrap();
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM snapshots", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn groups_create_exists_conflict() {
        let (_d, mut c) = store();
        assert_eq!(
            create_group(&mut c, "g", &[1; 32], 0).unwrap(),
            CreateGroup::Created
        );
        assert_eq!(
            create_group(&mut c, "g", &[1; 32], 0).unwrap(),
            CreateGroup::Exists
        );
        assert_eq!(
            create_group(&mut c, "g", &[2; 32], 0).unwrap(),
            CreateGroup::Conflict
        );
        assert_eq!(group_key(&mut c, "g").unwrap(), Some([1; 32]));
        assert_eq!(group_key(&mut c, "h").unwrap(), None);
    }

    #[test]
    fn message_cap_and_sequence() {
        let (_d, mut c) = store();
        create_group(&mut c, "g", &[1; 32], 0).unwrap();
        for i in 0..(MAX_MESSAGES + 5) {
            insert_message(&mut c, "g", &msg(&format!("m{i}")), 10).unwrap();
        }
        assert_eq!(counts(&mut c, "g").unwrap().0, MAX_MESSAGES);
        assert_eq!(
            insert_message(&mut c, "g", &msg("m504"), 10).unwrap(),
            Insert::Duplicate(505)
        );
        let (page, more) = messages_since(&mut c, "g", 0, 10).unwrap();
        assert_eq!(page.len(), PAGE);
        assert!(more);
        assert_eq!(page[0].cursor, 6, "oldest five evicted");
    }

    #[test]
    fn command_cap() {
        let (_d, mut c) = store();
        create_group(&mut c, "g", &[1; 32], 0).unwrap();
        for i in 0..MAX_COMMANDS {
            assert!(matches!(
                insert_command(&mut c, "g", &format!("c{i}"), "AAAA", 10).unwrap(),
                Insert::Stored(_)
            ));
        }
        assert_eq!(
            insert_command(&mut c, "g", "x", "AAAA", 10).unwrap(),
            Insert::Full
        );
        assert!(ack_command(&mut c, "g", 1).unwrap());
        assert!(!ack_command(&mut c, "g", 1).unwrap());
        assert_eq!(
            insert_command(&mut c, "g", "x", "AAAA", 10).unwrap(),
            Insert::Stored(201)
        );
    }

    #[test]
    fn activity_tokens_replace_cascade_and_summaries_keep_newest() {
        let (_d, mut c) = store();
        create_group(&mut c, "g", &[1; 32], 0).unwrap();
        let phone = Device {
            device_id: "p".into(),
            kind: "ios".into(),
            name: "iPhone".into(),
            apns_token: None,
            apns_env: "sandbox".into(),
            created_at: 0,
            updated_at: 0,
            last_seen: None,
        };
        upsert_device(&mut c, "g", &phone, 1).unwrap();
        assert!(put_activity_token(&mut c, "g", "p", "update", "aa", "sandbox", 5, 5).unwrap());
        assert!(!put_activity_token(&mut c, "g", "p", "update", "bb", "sandbox", 6, 6).unwrap());
        assert!(put_activity_token(&mut c, "g", "p", "start", "cc", "sandbox", 6, 6).unwrap());
        let t = activity_tokens(&mut c, "g").unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(
            (
                t[1].kind.as_str(),
                t[1].push_token.as_str(),
                t[1].started_at
            ),
            ("update", "bb", 6)
        );
        assert!(
            !clear_activity_token(&mut c, "g", "p", "update", "aa").unwrap(),
            "replaced"
        );
        assert_eq!(delete_update_tokens(&mut c, "g", Some(5)).unwrap(), 0);
        assert_eq!(delete_update_tokens(&mut c, "g", Some(6)).unwrap(), 1);
        delete_device(&mut c, "g", "p").unwrap();
        assert!(activity_tokens(&mut c, "g").unwrap().is_empty(), "cascade");

        let mut m = msg("s1");
        m.kind = "summary".into();
        insert_message(&mut c, "g", &m, 10).unwrap();
        insert_message(&mut c, "g", &msg("a1"), 10).unwrap();
        m.id = "s2".into();
        insert_message(&mut c, "g", &m, 11).unwrap();
        let (rows, _) = messages_since(&mut c, "g", 0, 11).unwrap();
        let ids: Vec<_> = rows.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["a1", "s2"]);
    }

    fn lic(id: &str) -> VerifiedLicence {
        VerifiedLicence {
            kind: "app_transaction",
            tier: "founder",
            environment: "production",
            app_transaction_id: id.into(),
            original_purchase_date: Some(1),
            original_application_version: Some("1.0".into()),
            original_platform: Some("macOS".into()),
            signed_date: 2,
        }
    }

    #[test]
    fn licences_attach_refresh_cap_and_cascade() {
        let (_d, mut c) = store();
        for g in ["a", "b", "c"] {
            create_group(&mut c, g, &[1; 32], 0).unwrap();
            assert_eq!(
                attach_licence(&mut c, g, &lic("p1"), 2, 10).unwrap(),
                if g == "c" {
                    Attach::InUse
                } else {
                    Attach::Attached
                }
            );
        }
        assert_eq!(group_licence(&mut c, "c").unwrap(), None);
        assert_eq!(
            attach_licence(&mut c, "a", &lic("p1"), 2, 20).unwrap(),
            Attach::Refreshed
        );
        let l = group_licence(&mut c, "a").unwrap().unwrap();
        assert_eq!((l.tier.as_str(), l.verified_at), ("founder", 20));

        // Refused on create: the group is rolled back.
        let (created, attach) =
            create_group_with_licence(&mut c, "d", &[1; 32], &lic("p1"), 2, 30).unwrap();
        assert_eq!((created, attach), (CreateGroup::Created, Attach::InUse));
        assert_eq!(group_key(&mut c, "d").unwrap(), None);

        // Deleting a group frees its slot and cascades.
        upsert_device(
            &mut c,
            "a",
            &Device {
                device_id: "mac".into(),
                kind: "mac".into(),
                name: "Mac".into(),
                apns_token: None,
                apns_env: "production".into(),
                created_at: 0,
                updated_at: 0,
                last_seen: None,
            },
            1,
        )
        .unwrap();
        insert_message(&mut c, "a", &msg("m"), 10).unwrap();
        assert!(delete_group(&mut c, "a").unwrap());
        assert!(!delete_group(&mut c, "a").unwrap());
        assert_eq!(counts(&mut c, "a").unwrap(), (0, 0));
        assert!(list_devices(&mut c, "a").unwrap().is_empty());
        assert_eq!(group_licence(&mut c, "a").unwrap(), None);
        assert_eq!(
            create_group_with_licence(&mut c, "d", &[1; 32], &lic("p1"), 2, 40).unwrap(),
            (CreateGroup::Created, Attach::Attached)
        );
    }

    #[test]
    fn last_seen_is_kept_across_upserts() {
        let (_d, mut c) = store();
        create_group(&mut c, "g", &[1; 32], 0).unwrap();
        let d = Device {
            device_id: "mac".into(),
            kind: "mac".into(),
            name: "Mac".into(),
            apns_token: None,
            apns_env: "production".into(),
            created_at: 0,
            updated_at: 0,
            last_seen: None,
        };
        upsert_device(&mut c, "g", &d, 10).unwrap();
        assert_eq!(device(&mut c, "g", "mac").unwrap().unwrap().last_seen, None);
        touch_device(&mut c, "g", "mac", 42).unwrap();
        upsert_device(&mut c, "g", &d, 50).unwrap();
        assert_eq!(
            device(&mut c, "g", "mac").unwrap().unwrap().last_seen,
            Some(42)
        );
    }
}
