-- Exact schema created by create_all at commit 5c1c232 (Phase 1-3). Captured
-- with `sqlite3 .schema`; used by test_migrations.py. Do not edit.
CREATE TABLE ai_explanations (
	id INTEGER NOT NULL, 
	vuln_id VARCHAR(100) NOT NULL, 
	model VARCHAR(100) NOT NULL, 
	summary VARCHAR NOT NULL, 
	attack_scenario VARCHAR NOT NULL, 
	project_impact VARCHAR NOT NULL, 
	fix_steps VARCHAR NOT NULL, 
	priority VARCHAR(30) NOT NULL, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_vuln_model UNIQUE (vuln_id, model)
);
CREATE INDEX ix_ai_explanations_vuln_id ON ai_explanations (vuln_id);
CREATE TABLE scans (
	id INTEGER NOT NULL, 
	filename VARCHAR(255) NOT NULL, 
	created_at DATETIME NOT NULL, 
	total_dependencies INTEGER NOT NULL, 
	vulnerable_dependencies INTEGER NOT NULL, 
	risk_score INTEGER NOT NULL, 
	risk_level VARCHAR(20) NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE scan_dependencies (
	id INTEGER NOT NULL, 
	scan_id INTEGER NOT NULL, 
	name VARCHAR(255) NOT NULL, 
	version VARCHAR(100), 
	ecosystem VARCHAR(50) NOT NULL, 
	pinned BOOLEAN NOT NULL, 
	raw_spec VARCHAR(255) NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE
);
CREATE TABLE scan_vulnerabilities (
	id INTEGER NOT NULL, 
	scan_id INTEGER NOT NULL, 
	dependency_id INTEGER NOT NULL, 
	vuln_id VARCHAR(100) NOT NULL, 
	summary VARCHAR NOT NULL, 
	details VARCHAR NOT NULL, 
	aliases JSON NOT NULL, 
	severity VARCHAR(20) NOT NULL, 
	cvss_score FLOAT, 
	cvss_vector VARCHAR(200), 
	fixed_version VARCHAR(200), 
	"references" JSON NOT NULL, 
	in_cisa_kev BOOLEAN NOT NULL, 
	risk_score INTEGER NOT NULL, 
	risk_level VARCHAR(20) NOT NULL, 
	reachability VARCHAR(30) NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE, 
	FOREIGN KEY(dependency_id) REFERENCES scan_dependencies (id) ON DELETE CASCADE
);
