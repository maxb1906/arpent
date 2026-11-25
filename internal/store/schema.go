package store

// migrations : chaque entrée fait passer la base de la version i à i+1
// (PRAGMA user_version). Ne jamais modifier une migration publiée : en
// ajouter une nouvelle.
var migrations = []string{
	// 1 — schéma initial (§ 6).
	`
CREATE TABLE site (
	id         INTEGER PRIMARY KEY CHECK (id = 1),
	name       TEXT NOT NULL,
	slug       TEXT NOT NULL,
	address    TEXT NOT NULL DEFAULT '',
	contact    TEXT NOT NULL DEFAULT '',
	notes      TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL
);

CREATE TABLE audit (
	id            INTEGER PRIMARY KEY,
	started_at    TEXT NOT NULL,
	finished_at   TEXT,
	status        TEXT NOT NULL,              -- running, done, failed, cancelled
	technician    TEXT NOT NULL DEFAULT '',
	ranges        TEXT NOT NULL DEFAULT '',   -- plages saisies
	profile       TEXT NOT NULL,
	mode          TEXT NOT NULL DEFAULT 'standard',
	targets       INTEGER NOT NULL DEFAULT 0,
	authorized_at TEXT,                       -- confirmation « autorisé à auditer »
	authorized_by TEXT NOT NULL DEFAULT '',
	error         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE device (
	id          INTEGER PRIMARY KEY,
	identity    TEXT NOT NULL UNIQUE,         -- mac:… ou ip:…|nom
	mac         TEXT NOT NULL DEFAULT '',
	label       TEXT NOT NULL DEFAULT '',     -- nom convivial
	location    TEXT NOT NULL DEFAULT '',
	owner       TEXT NOT NULL DEFAULT '',
	notes       TEXT NOT NULL DEFAULT '',
	known       INTEGER NOT NULL DEFAULT 0,   -- connu / validé
	known_at    TEXT,
	first_audit INTEGER REFERENCES audit(id),
	last_audit  INTEGER REFERENCES audit(id)
);

CREATE TABLE observation (
	id          INTEGER PRIMARY KEY,
	audit_id    INTEGER NOT NULL REFERENCES audit(id) ON DELETE CASCADE,
	device_id   INTEGER NOT NULL REFERENCES device(id),
	ip          TEXT NOT NULL,
	mac         TEXT NOT NULL DEFAULT '',
	vendor      TEXT NOT NULL DEFAULT '',
	random_mac  INTEGER NOT NULL DEFAULT 0,
	names       TEXT NOT NULL DEFAULT '[]',   -- JSON
	methods     TEXT NOT NULL DEFAULT '[]',   -- JSON
	device_type TEXT NOT NULL DEFAULT '',
	rtt_us      INTEGER NOT NULL DEFAULT 0,
	UNIQUE (audit_id, device_id)
);
CREATE INDEX observation_device ON observation(device_id);

CREATE TABLE service (
	id             INTEGER PRIMARY KEY,
	observation_id INTEGER NOT NULL REFERENCES observation(id) ON DELETE CASCADE,
	port           INTEGER NOT NULL,
	proto          TEXT NOT NULL,
	state          TEXT NOT NULL DEFAULT 'open',
	name           TEXT NOT NULL DEFAULT '',
	product        TEXT NOT NULL DEFAULT '',
	version        TEXT NOT NULL DEFAULT '',
	banner         TEXT NOT NULL DEFAULT '',
	details        TEXT NOT NULL DEFAULT '{}', -- JSON (HTTP, TLS, SSH…)
	raw            BLOB,
	UNIQUE (observation_id, port, proto)
);

CREATE TABLE finding (
	id         INTEGER PRIMARY KEY,
	audit_id   INTEGER NOT NULL REFERENCES audit(id) ON DELETE CASCADE,
	device_id  INTEGER NOT NULL REFERENCES device(id),
	service_id INTEGER REFERENCES service(id) ON DELETE CASCADE,
	rule       TEXT NOT NULL,                -- identifiant de règle
	level      TEXT NOT NULL,                -- info, warning, critical
	params     TEXT NOT NULL DEFAULT '{}'    -- JSON : variables du texte traduit
);
CREATE INDEX finding_audit ON finding(audit_id);

CREATE TABLE change (
	id         INTEGER PRIMARY KEY,
	audit_id   INTEGER NOT NULL REFERENCES audit(id) ON DELETE CASCADE,
	prev_audit INTEGER REFERENCES audit(id) ON DELETE SET NULL,
	kind       TEXT NOT NULL,                -- new_device, gone_device, port_opened…
	device_id  INTEGER REFERENCES device(id),
	port       INTEGER,
	proto      TEXT,
	before     TEXT NOT NULL DEFAULT '',
	after      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX change_audit ON change(audit_id);
`,
	// 2 — informations des protocoles de découverte (NetBIOS, mDNS, SSDP…).
	`ALTER TABLE observation ADD COLUMN extra TEXT NOT NULL DEFAULT '{}';`,
}
