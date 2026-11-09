//! SQLite persistence for v2: groups, devices, the message mailbox and the
//! command queue. Blobs stored here are opaque ciphertext (see PROTOCOL.md).
//!
//! One connection behind a mutex; every call runs on the blocking pool so the
//! async workers never wait on disk.

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension};
use subtle::ConstantTimeEq;

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
];

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

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
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
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
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

fn ts(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

pub fn create_group(
    c: &mut Connection,
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

/// Delete expired messages and commands; returns (messages, commands) removed.
pub fn cleanup(c: &mut Connection, now: u64) -> Result<(usize, usize), StoreError> {
    let m = c.execute(
        "DELETE FROM messages WHERE created_at <= ?1",
        [cutoff(now, MESSAGE_RETENTION_SECS)],
    )?;
    let k = c.execute(
        "DELETE FROM commands WHERE created_at <= ?1",
        [cutoff(now, COMMAND_RETENTION_SECS)],
    )?;
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
