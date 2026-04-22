-- NetScan database schema (SQLite / Postgres compatible)
-- Auto-created by SQLAlchemy, but provided here for reference.

CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  VARCHAR(64) NOT NULL UNIQUE,
    mac_address VARCHAR(20),
    hostname    VARCHAR(200),
    owner       VARCHAR(200),
    last_seen   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS network_features (
    id                            INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start                  TIMESTAMP NOT NULL,
    window_end                    TIMESTAMP NOT NULL,
    src_ip                        VARCHAR(64) NOT NULL,
    dst_category                  VARCHAR(64),
    num_flows                     INTEGER DEFAULT 0,
    num_unique_dst_ips            INTEGER DEFAULT 0,
    num_unique_domains            INTEGER DEFAULT 0,
    total_bytes_sent              BIGINT  DEFAULT 0,
    total_bytes_received          BIGINT  DEFAULT 0,
    avg_packet_size               REAL    DEFAULT 0.0,
    std_packet_size               REAL    DEFAULT 0.0,
    avg_inter_packet_time         REAL    DEFAULT 0.0,
    std_inter_packet_time         REAL    DEFAULT 0.0,
    tcp_flow_count                INTEGER DEFAULT 0,
    udp_flow_count                INTEGER DEFAULT 0,
    dns_query_count               INTEGER DEFAULT 0,
    distinct_dst_ports            INTEGER DEFAULT 0,
    top_port                      INTEGER,
    ratio_known_vpn_ips           REAL    DEFAULT 0.0,
    ratio_known_restricted_domains REAL   DEFAULT 0.0,
    extra                         TEXT    DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_nf_window_start ON network_features(window_start);
CREATE INDEX IF NOT EXISTS idx_nf_src_ip_window ON network_features(src_ip, window_start);

CREATE TABLE IF NOT EXISTS detections (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    feature_id    INTEGER REFERENCES network_features(id),
    src_ip        VARCHAR(64) NOT NULL,
    window_start  TIMESTAMP NOT NULL,
    window_end    TIMESTAMP NOT NULL,
    rule_hits     TEXT    DEFAULT '{}',
    rule_score    REAL    DEFAULT 0.0,
    ml_score      REAL    DEFAULT 0.0,
    combined_risk REAL    DEFAULT 0.0,
    decision      VARCHAR(32) DEFAULT 'allow',
    needs_ai      BOOLEAN DEFAULT 0,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_det_src_ip ON detections(src_ip);
CREATE INDEX IF NOT EXISTS idx_det_feature ON detections(feature_id);

CREATE TABLE IF NOT EXISTS ai_assessments (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id       INTEGER REFERENCES detections(id),
    threat_type        VARCHAR(64)  DEFAULT 'unknown',
    severity           VARCHAR(16)  DEFAULT 'low',
    explanation        TEXT         DEFAULT '',
    recommended_action TEXT         DEFAULT '',
    raw_response       TEXT         DEFAULT '{}',
    created_at         TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ai_det ON ai_assessments(detection_id);

CREATE TABLE IF NOT EXISTS alerts (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id      INTEGER REFERENCES detections(id),
    ai_assessment_id  INTEGER REFERENCES ai_assessments(id),
    src_ip            VARCHAR(64) NOT NULL,
    window_start      TIMESTAMP NOT NULL,
    window_end        TIMESTAMP NOT NULL,
    title             VARCHAR(200) NOT NULL,
    summary           TEXT NOT NULL,
    severity          VARCHAR(16) NOT NULL,
    threat_type       VARCHAR(64) NOT NULL,
    status            VARCHAR(16) DEFAULT 'open',
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at       TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alert_src ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alert_created ON alerts(created_at);
