import sqlite3
import json
from pathlib import Path
from datetime import datetime
from core.models import Target, Connection, Finding
from core.logger import get_logger
import config

log = get_logger("db")


def _connect() -> sqlite3.Connection:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(config.DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS engagements (
            id          TEXT PRIMARY KEY,
            name        TEXT,
            location    TEXT,
            started_at  TEXT,
            notes       TEXT
        );

        CREATE TABLE IF NOT EXISTS targets (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id   TEXT,
            bd_address      TEXT,
            address_type    TEXT,
            adv_type        TEXT,
            name            TEXT,
            manufacturer    TEXT,
            company_id      INTEGER,
            services        TEXT,   -- JSON array
            tx_power        INTEGER,
            rssi_avg        REAL,
            device_class    TEXT,
            connectable     INTEGER,
            risk_score      INTEGER,
            first_seen      TEXT,
            last_seen       TEXT,
            UNIQUE(engagement_id, bd_address)
        );

        CREATE TABLE IF NOT EXISTS connections (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id           TEXT,
            central_addr            TEXT,
            peripheral_addr         TEXT,
            access_address          INTEGER,
            crc_init                INTEGER,
            interval_ms             REAL,
            channel_map             TEXT,
            hop_increment           INTEGER,
            encrypted               INTEGER,
            legacy_pairing_observed INTEGER,
            pairing_pcap_path       TEXT,
            plaintext_data_captured INTEGER,
            data_pcap_path          TEXT,
            timestamp               TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id   TEXT,
            type            TEXT,
            severity        TEXT,
            target_addr     TEXT,
            description     TEXT,
            remediation     TEXT,
            evidence        TEXT,   -- JSON
            pcap_path       TEXT,
            timestamp       TEXT
        );
        """)
    log.info(f"Database ready: {config.DB_PATH}")


def upsert_engagement(eng_id: str, name: str, location: str, notes: str = "") -> None:
    with _connect() as conn:
        conn.execute("""
            INSERT INTO engagements (id, name, location, started_at, notes)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET notes=excluded.notes
        """, (eng_id, name, location, datetime.utcnow().isoformat(), notes))


def upsert_target(t: Target) -> None:
    with _connect() as conn:
        conn.execute("""
            INSERT INTO targets
                (engagement_id, bd_address, address_type, adv_type, name,
                 manufacturer, company_id, services, tx_power, rssi_avg,
                 device_class, connectable, risk_score, first_seen, last_seen)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(engagement_id, bd_address) DO UPDATE SET
                name            = excluded.name,
                manufacturer    = excluded.manufacturer,
                services        = excluded.services,
                tx_power        = excluded.tx_power,
                rssi_avg        = excluded.rssi_avg,
                device_class    = excluded.device_class,
                connectable     = excluded.connectable,
                risk_score      = excluded.risk_score,
                last_seen       = excluded.last_seen
        """, (
            t.engagement_id, t.bd_address, t.address_type, t.adv_type,
            t.name, t.manufacturer, t.company_id,
            json.dumps(t.services), t.tx_power, t.rssi_avg,
            t.device_class, int(t.connectable), t.risk_score,
            t.first_seen.isoformat(), t.last_seen.isoformat()
        ))


def insert_connection(c: Connection) -> None:
    with _connect() as conn:
        conn.execute("""
            INSERT INTO connections
                (engagement_id, central_addr, peripheral_addr, access_address,
                 crc_init, interval_ms, channel_map, hop_increment,
                 encrypted, legacy_pairing_observed, pairing_pcap_path,
                 plaintext_data_captured, data_pcap_path, timestamp)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            c.engagement_id, c.central_addr, c.peripheral_addr,
            c.access_address, c.crc_init, c.interval_ms, c.channel_map,
            c.hop_increment, int(c.encrypted), int(c.legacy_pairing_observed),
            c.pairing_pcap_path, int(c.plaintext_data_captured),
            c.data_pcap_path, c.timestamp.isoformat()
        ))


def insert_finding(f: Finding) -> None:
    with _connect() as conn:
        conn.execute("""
            INSERT INTO findings
                (engagement_id, type, severity, target_addr,
                 description, remediation, evidence, pcap_path, timestamp)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            f.engagement_id, f.type, f.severity, f.target_addr,
            f.description, f.remediation,
            json.dumps(f.evidence), f.pcap_path,
            f.timestamp.isoformat()
        ))


def get_targets(engagement_id: str) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM targets WHERE engagement_id=? ORDER BY risk_score DESC",
            (engagement_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_connections(engagement_id: str) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM connections WHERE engagement_id=? ORDER BY timestamp",
            (engagement_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_findings(engagement_id: str) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE engagement_id=? ORDER BY severity",
            (engagement_id,)
        ).fetchall()
    return [dict(r) for r in rows]
