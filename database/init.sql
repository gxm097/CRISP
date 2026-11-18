
--Organization
CREATE TABLE Organization
(
    OrganizationID SERIAL PRIMARY KEY,
    OrganizationName VARCHAR(100) NOT NULL,
    CreatedDate TIMESTAMP NOT NULL,
    Status VARCHAR(20) NOT NULL
);
INSERT INTO Organization
(
    OrganizationName,
    CreatedDate,
    Status
)
VALUES
(
    'SpawGlass',
    CURRENT_TIMESTAMP,
    'Active'
);

-- User Account
CREATE TABLE user_account
(
    user_id SERIAL PRIMARY KEY,

    organization_id INTEGER NOT NULL
        REFERENCES organization(organizationid),

    username VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,

    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    account_status VARCHAR(30) NOT NULL DEFAULT 'Active',

    UNIQUE (organization_id, username),
    UNIQUE (organization_id, email)
);

INSERT INTO user_account
(
    organization_id,
    username,
    password_hash,
    email,
    role,
    mfa_enabled,
    account_status
)
VALUES
(
    1,
    'testadmin',
    '$2b$10$8TVe9VwYDNXJy2ciMN4ZiuEmvVzc7S.YULJlcLL9T34WP4Sh8z5pi',
    'testadmin@example.com',
    'Account Administrator',
    TRUE,
    'Active'
);

--Asset Type 
CREATE TABLE AssetType
(
    AssetTypeID SERIAL PRIMARY KEY,

    AssetTypeName VARCHAR(100) NOT NULL UNIQUE
);

INSERT INTO AssetType
(
    AssetTypeName
)
VALUES
('Firewall'),
('VPN Endpoint'),
('Switch'),
('Access Point'),
('SaaS');

--Vulnerability Source
CREATE TABLE VulnerabilitySource
(
    SourceID SERIAL PRIMARY KEY,

    SourceName VARCHAR(150) NOT NULL,

    Description TEXT,

    BaseURL VARCHAR(500),

    SourceType VARCHAR(50),

    Enabled BOOLEAN NOT NULL DEFAULT TRUE
);

INSERT INTO VulnerabilitySource
(
    SourceName,
    Description,
    BaseURL,
    SourceType
)
VALUES
(
    'NVD',
    'National Vulnerability Database',
    'https://nvd.nist.gov',
    'Database'
),
(
    'CISA',
    'Cybersecurity and Infrastructure Security Agency',
    'https://www.cisa.gov',
    'Government'
),
(
    'MITRE CVE',
    'Common Vulnerabilities and Exposures',
    'https://www.cve.org',
    'Database'
);

--Vulnerability
CREATE TABLE Vulnerability
(
    VulnerabilityID SERIAL PRIMARY KEY,

    CVE VARCHAR(30) UNIQUE,

    Title VARCHAR(255) NOT NULL,

    Description TEXT,

    CVSSScore DECIMAL(3,1),

    Severity VARCHAR(30),

    ExploitStatus VARCHAR(50),

    KEVFlag BOOLEAN DEFAULT FALSE,

    FirstPublished TIMESTAMP,

    LastUpdated TIMESTAMP,

    CHECK
    (
        CVSSScore IS NULL OR
        (CVSSScore >= 0 AND CVSSScore <= 10)
    )
);

INSERT INTO Vulnerability
(
    CVE,
    Title,
    Description,
    CVSSScore,
    Severity,
    ExploitStatus,
    KEVFlag,
    FirstPublished
)
VALUES
(
    'CVE-2026-0001',
    'Example FortiGate Vulnerability',
    'Testing vulnerability table.',
    9.8,
    'Critical',
    'Known Exploited',
    TRUE,
    CURRENT_TIMESTAMP
),
(
    'CVE-2026-0002',
    'Example Cisco AnyConnect Vulnerability',
    'Testing vulnerability table.',
    7.5,
    'High',
    'Exploitable',
    FALSE,
    CURRENT_TIMESTAMP
),(
    'CVE-2026-0003',
    'Example Cisco Catalyst Vulnerability',
    'Testing vulnerability table.',
    5.0,
    'Medium',
    'Exploitable',
    FALSE,
    CURRENT_TIMESTAMP
),(
    'CVE-2026-0004',
    'Example Ubiquiti UniFi AP Vulnerability',
    'Testing vulnerability table.',
    4.3,
    'Low',
    'Exploitable',
    FALSE,
    CURRENT_TIMESTAMP
),
(
    'CVE-2026-0005',
    'Example Microsoft Office 365 Vulnerability',
    'Testing vulnerability table.',
    8.2,
    'High',
    'Exploitable',
    FALSE,
    CURRENT_TIMESTAMP
);

--Vulnerability Affected Version
CREATE TABLE VulnerabilityAffectedVersion
(
    AffectedVersionID SERIAL PRIMARY KEY,

    VulnerabilityID INT NOT NULL,

    VersionStart VARCHAR(50),

    VersionEnd VARCHAR(50),

    VersionStartKey INT[],

    VersionEndKey INT[],

    FOREIGN KEY (VulnerabilityID)
        REFERENCES Vulnerability(VulnerabilityID)
        ON DELETE CASCADE
);

CREATE INDEX idx_affected_vulnerability
ON VulnerabilityAffectedVersion(VulnerabilityID);

--Inventory Import
CREATE TABLE InventoryImport
(
    ImportID SERIAL PRIMARY KEY,

    OrganizationID INT NOT NULL,

    UploadedByUserID INT NOT NULL,

    Filename VARCHAR(255) NOT NULL,

    UploadDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (OrganizationID)
        REFERENCES Organization(OrganizationID),

    FOREIGN KEY (UploadedByUserID)
        REFERENCES user_account(user_id)
);

INSERT INTO InventoryImport
(
    OrganizationID,
    UploadedByUserID,
    Filename
)
VALUES
(
    1,
    1,
    'spawglass_inventory_october.csv'
);

--Inventory Assests
CREATE TABLE InventoryAsset
(
    AssetID SERIAL PRIMARY KEY,

    OrganizationID INT NOT NULL,

    ImportID INT NULL,

    AssetTypeID INT NOT NULL,

    AssetName VARCHAR(255) NOT NULL,

    Vendor VARCHAR(150),

    Product VARCHAR(150),

    Version VARCHAR(100),

    Build VARCHAR(100),

    Hostname VARCHAR(255),

    Description TEXT,

    PublicFacing BOOLEAN DEFAULT FALSE,

    Status VARCHAR(30) DEFAULT 'Active',

    AssetCreatedDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    AssetLastUpdated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (OrganizationID)
        REFERENCES Organization(OrganizationID),

    FOREIGN KEY (ImportID)
        REFERENCES InventoryImport(ImportID)
        ON DELETE SET NULL,

    FOREIGN KEY (AssetTypeID)
        REFERENCES AssetType(AssetTypeID)
);

CREATE INDEX idx_asset_org
ON InventoryAsset(OrganizationID);

CREATE INDEX idx_asset_product
ON InventoryAsset(Vendor, Product, Version);

INSERT INTO InventoryAsset
(
    OrganizationID,
    AssetTypeID,
    AssetName,
    Vendor,
    Product,
    Version,
    PublicFacing
)
VALUES
(
    1,
    1,
    'Firewall-01',
    'Fortinet',
    'FortiGate-80F',
    '7.2.10',
    TRUE
),
(
    1,
    2,
    'VPN-Endpoint-01',
    'Cisco',
    'AnyConnect',
    '4.10.04049',
    TRUE
),
(
    1,
    3,
    'Switch-01',
    'Cisco',
    'Catalyst 9300',
    '17.3.3',
    FALSE
),
(
    1,
    4,
    'AccessPoint-01',
    'Ubiquiti',
    'UniFi AP AC Pro',
    '4.0.80.10875',
    FALSE
),
(
    1,
    5,
    'SaaS-01',
    'Microsoft',
    'Office 365',
    NULL,
    FALSE
);

--VulnerabilitySourceReference
CREATE TABLE VulnerabilitySourceReference
(
    ReferenceID SERIAL PRIMARY KEY,

    VulnerabilityID INT NOT NULL,

    SourceID INT NOT NULL,

    SourceURL VARCHAR(1000),

    RetrievedDate TIMESTAMP,

    FOREIGN KEY (VulnerabilityID)
        REFERENCES Vulnerability(VulnerabilityID),

    FOREIGN KEY (SourceID)
        REFERENCES VulnerabilitySource(SourceID),

    UNIQUE
    (
        VulnerabilityID,
        SourceID,
        SourceURL
    )
);

--Assessment Schedule
CREATE TABLE AssessmentSchedule
(
    ScheduleID SERIAL PRIMARY KEY,

    OrganizationID INT NOT NULL,

    Frequency VARCHAR(50) NOT NULL,

    Enabled BOOLEAN DEFAULT TRUE,

    LastRun TIMESTAMP NULL,

    NextRun TIMESTAMP NULL,

    FOREIGN KEY (OrganizationID)
        REFERENCES Organization(OrganizationID)
);

INSERT INTO AssessmentSchedule
(
    OrganizationID,
    Frequency,
    Enabled
)
VALUES
(
    1,
    'Daily',
    TRUE
);

--Assessments
CREATE TABLE Assessment
(
    AssessmentID SERIAL PRIMARY KEY,

    OrganizationID INT NOT NULL,

    AssessmentStart TIMESTAMP,

    AssessmentEnd TIMESTAMP,

    TriggerType VARCHAR(50),

    Status VARCHAR(30) DEFAULT 'Pending',

    FOREIGN KEY (OrganizationID)
        REFERENCES Organization(OrganizationID)
);

CREATE INDEX idx_assessment_org
ON Assessment(OrganizationID);

INSERT INTO Assessment
(
    OrganizationID,
    AssessmentStart,
    TriggerType,
    Status
)
VALUES
(
    1,
    CURRENT_TIMESTAMP,
    'Manual',
    'Running'
);

--Assessment Asset
CREATE TABLE AssessmentAsset
(
    AssessmentID INT NOT NULL,

    AssetID INT NOT NULL,

    AssetSnapshotVersion VARCHAR(100),

    EvaluationStatus VARCHAR(50),

    PRIMARY KEY (AssessmentID, AssetID),

    FOREIGN KEY (AssessmentID)
        REFERENCES Assessment(AssessmentID)
        ON DELETE CASCADE,

    FOREIGN KEY (AssetID)
        REFERENCES InventoryAsset(AssetID)
        ON DELETE CASCADE
);

INSERT INTO AssessmentAsset
(
    AssessmentID,
    AssetID,
    AssetSnapshotVersion,
    EvaluationStatus
)
VALUES
(
    1,
    1,
    '7.2.10',
    'Evaluated'
);

--Research Results

CREATE TABLE ResearchResult
(
    ResearchResultID SERIAL PRIMARY KEY,

    AssessmentID INT NOT NULL,

    SourceID INT NOT NULL,

    AssetID INT NULL,

    QueryText TEXT,

    RetrievedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    Status VARCHAR(50),

    RawContent TEXT,

    SourceURL VARCHAR(1000),

    FOREIGN KEY (AssessmentID)
        REFERENCES Assessment(AssessmentID)
        ON DELETE CASCADE,

    FOREIGN KEY (SourceID)
        REFERENCES VulnerabilitySource(SourceID),

    FOREIGN KEY (AssetID)
        REFERENCES InventoryAsset(AssetID)
        ON DELETE SET NULL
);

INSERT INTO ResearchResult
(
    AssessmentID,
    SourceID,
    AssetID,
    QueryText,
    Status,
    SourceURL
)
VALUES
(
    1,
    1,
    1,
    'FortiGate-80F vulnerabilities',
    'Completed',
    'https://example.com'
);

--Finding

CREATE TABLE Finding
(
    FindingID SERIAL PRIMARY KEY,

    OrganizationID INT NOT NULL,

    AssetID INT NOT NULL,

    VulnerabilityID INT NOT NULL,

    Priority VARCHAR(30) NOT NULL,

    FindingStatus VARCHAR(50) DEFAULT 'Open',

    FirstDetected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    LastVerified TIMESTAMP NULL,

    FOREIGN KEY (OrganizationID)
        REFERENCES Organization(OrganizationID),

    FOREIGN KEY (AssetID)
        REFERENCES InventoryAsset(AssetID),

    FOREIGN KEY (VulnerabilityID)
        REFERENCES Vulnerability(VulnerabilityID)
);

CREATE INDEX idx_finding_status
ON Finding(FindingStatus);

CREATE INDEX idx_finding_priority
ON Finding(Priority);

INSERT INTO Finding
(
    OrganizationID,
    AssetID,
    VulnerabilityID,
    Priority
)
VALUES
(
    1,
    1,
    1,
    'Critical'
);

--Finding Verification
CREATE TABLE FindingVerification
(
    FindingVerificationID SERIAL PRIMARY KEY,

    FindingID INT NOT NULL,

    QAResultID INT NOT NULL UNIQUE,

    AssessmentID INT NOT NULL,

    VerifiedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (FindingID)
        REFERENCES Finding(FindingID),

    FOREIGN KEY (AssessmentID)
        REFERENCES Assessment(AssessmentID)
);

--Report
CREATE TABLE Report
(
    ReportID SERIAL PRIMARY KEY,

    OrganizationID INT NOT NULL,

    GeneratedByUserID INT NOT NULL,

    ReportType VARCHAR(50),

    CreatedDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    PeriodStart DATE,

    PeriodEnd DATE,

    FOREIGN KEY (OrganizationID)
        REFERENCES Organization(OrganizationID),

    FOREIGN KEY (GeneratedByUserID)
        REFERENCES user_account(user_id)
);

INSERT INTO Report
(
    OrganizationID,
    GeneratedByUserID,
    ReportType,
    PeriodStart,
    PeriodEnd
)
VALUES
(
    1,
    1,
    'Assessment Summary',
    '2026-11-01',
    '2026-11-30'
);

--Audit Event
CREATE TABLE AuditEvent
(
    AuditID SERIAL PRIMARY KEY,

    UserID INT NULL,

    EventType VARCHAR(100) NOT NULL,

    EventTime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    EntityType VARCHAR(100),

    EntityID INT,

    FOREIGN KEY (UserID)
        REFERENCES user_account(user_id)
        ON DELETE SET NULL
);

INSERT INTO AuditEvent
(
    UserID,
    EventType,
    EntityType,
    EntityID
)
VALUES
(
    1,
    'User Login',
    'UserAccount',
    1
);

--Correlation
CREATE TABLE Correlation
(
    CorrelationID SERIAL PRIMARY KEY,

    AssessmentID INT NOT NULL,

    AssetID INT NOT NULL,

    VulnerabilityID INT NOT NULL,

    PotentiallyVulnerable BOOLEAN NOT NULL,
    
    UNIQUE
(
    AssessmentID,
    AssetID,
    VulnerabilityID
),

    FOREIGN KEY (AssessmentID)
        REFERENCES Assessment(AssessmentID)
        ON DELETE CASCADE,

    FOREIGN KEY (AssetID)
        REFERENCES InventoryAsset(AssetID),

    FOREIGN KEY (VulnerabilityID)
        REFERENCES Vulnerability(VulnerabilityID)
);

CREATE INDEX idx_correlation_asset_vuln
ON Correlation(AssetID, VulnerabilityID);

INSERT INTO Correlation
(
    AssessmentID,
    AssetID,
    VulnerabilityID,
    PotentiallyVulnerable,
    CorrelationType
)
VALUES
(
    1,
    1,
    1,
    TRUE,
    'Version Supported'
);

--Analyst Result
CREATE TABLE AnalystResult
(
    AnalysisResultID SERIAL PRIMARY KEY,

    CorrelationID INT NOT NULL UNIQUE,

    Determination TEXT,

    FOREIGN KEY (CorrelationID)
        REFERENCES Correlation(CorrelationID)
        ON DELETE CASCADE
);

INSERT INTO AnalystResult
(
    CorrelationID,
    Determination
)
VALUES
(
    1,
    'Applicable'
);

--QA Result
CREATE TABLE QAResult
(
    QAResultID SERIAL PRIMARY KEY,

    AnalysisResultID INT NOT NULL UNIQUE,

    Disposition VARCHAR(50) NOT NULL,

    FOREIGN KEY (AnalysisResultID)
        REFERENCES AnalystResult(AnalysisResultID)
);

ALTER TABLE FindingVerification
ADD CONSTRAINT fk_findingverification_qaresult
FOREIGN KEY (QAResultID)
REFERENCES QAResult(QAResultID);

INSERT INTO QAResult
(
    AnalysisResultID,
    Disposition
)
VALUES
(
    1,
    'Verified'
);

INSERT INTO FindingVerification
(
    FindingID,
    QAResultID,
    AssessmentID
)
VALUES
(
    1,
    1,
    1
);

