
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
    'admin',
    '$2b$10$8TVe9VwYDNXJy2ciMN4ZiuEmvVzc7S.YULJlcLL9T34WP4Sh8z5pi',
    'admin@example.com',
    'Account Administrator',
    TRUE,
    'Active'
),
(
    1,
    'analyst',
    '$2b$10$8TVe9VwYDNXJy2ciMN4ZiuEmvVzc7S.YULJlcLL9T34WP4Sh8z5pi',
    'analyst@example.com',
    'Analyst',
    FALSE,
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

    Vendor VARCHAR(50),

    Product VARCHAR(50),

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
    Vendor,
    Product,
    CVSSScore,
    Severity,
    ExploitStatus,
    KEVFlag,
    FirstPublished
)
VALUES
(
    'CVE-2025-59718',
    'FortiOS FortiCloud SSO authentication bypass via crafted SAML response',
    'An improper verification of cryptographic signature in FortiOS 7.2.0 through 7.2.11. An unauthenticated attacker can bypass FortiCloud SSO login authentication with a crafted SAML response message.',
    'Fortinet',
    'FortiOS',
    9.1,
    'Critical',
    'None',
    FALSE,
    '2025-12-09'
),
(
    'CVE-2022-0609',
    'Use after free in Animation',
    'Use after free in Animation in Google Chrome prior to 98.0.4758.102 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. Listed in CISA KEV.',
    'Google',
    'Google Chrome',
    8.8,
    'High',
    'Known Exploited',
    TRUE,
    '2022-04-04'
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

INSERT INTO VulnerabilityAffectedVersion
(
    VulnerabilityID,
    VersionStart,
    VersionEnd,
    VersionStartKey,
    VersionEndKey
)
VALUES
(
    1,
    '7.2.0',
    '7.2.11',
    ARRAY[7, 2, 0],
    ARRAY[7, 2, 11]
),
(
    2,
    NULL,
    '98.0.4758.102',
    NULL,
    ARRAY[98, 0, 4758, 102]
);

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
),
(
    1,
    1,
    'Google_Chrome_installation_export.csv'
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
    ImportID,
    AssetTypeID,
    AssetName,
    Vendor,
    Product,
    Version,
    Hostname,
    PublicFacing
)
VALUES
(
    1,
    1,
    1,
    'Firewall-01',
    'Fortinet',
    'FortiGate-80F',
    '7.2.10',
    'firewall-01.spawglass.local',
    TRUE
),
(
    1,
    2,
    5,
    'juanMarquez-Pc',
    'Google',
    'Google Chrome',
    '97.0.4692.99',
    'juanmarquez-pc.spawglass.local',
    FALSE
);

--Vulnerability Source Reference
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

INSERT INTO VulnerabilitySourceReference
(
    VulnerabilityID,
    SourceID,
    SourceURL,
    RetrievedDate
)
VALUES
(
    1,
    1,
    'https://nvd.nist.gov/vuln/detail/CVE-2025-59718',
    CURRENT_TIMESTAMP
),
(
    2,
    2,
    'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    CURRENT_TIMESTAMP
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
    Enabled,
    LastRun,
    NextRun
)
VALUES
(
    1,
    'Daily',
    TRUE,
    CURRENT_TIMESTAMP - INTERVAL '1 day',
    CURRENT_TIMESTAMP + INTERVAL '1 day'
),
(
    1,
    'Weekly',
    FALSE,
    NULL,
    CURRENT_TIMESTAMP + INTERVAL '7 days'
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
    AssessmentEnd,
    TriggerType,
    Status
)
VALUES
(
    1,
    CURRENT_TIMESTAMP - INTERVAL '1 day',
    CURRENT_TIMESTAMP - INTERVAL '1 day' + INTERVAL '18 minutes',
    'Manual',
    'Completed'
),
(
    1,
    CURRENT_TIMESTAMP,
    NULL,
    'Scheduled',
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
),
(
    1,
    2,
    '97.0.4692.99',
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
    RawContent,
    SourceURL
)
VALUES
(
    1,
    1,
    1,
    'find the CVEs affecting Fortinet FortiOS version 7.2.10',
    'Completed',
    '{"query": {"vendor": "Fortinet", "product": "FortiOS", "version": "7.2.10"}, "cves": [{"cve_id": "CVE-2025-59718", "title": "FortiOS FortiCloud SSO authentication bypass via crafted SAML response"}]}',
    'https://nvd.nist.gov/vuln/detail/CVE-2025-59718'
),
(
    1,
    2,
    2,
    'find the CVEs affecting Google Chrome version 97.0.4692.99',
    'Completed',
    '{"query": {"vendor": "Google", "product": "Google Chrome", "version": "97.0.4692.99"}, "cves": [{"cve_id": "CVE-2022-0609", "title": "Use after free in Animation"}]}',
    'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
);

--Finding
CREATE TABLE Finding
(
    FindingID SERIAL PRIMARY KEY,

    OrganizationID INT NOT NULL,

    AssetID INT NOT NULL,

    VulnerabilityID INT NOT NULL,

    Priority DECIMAL(3,1) NOT NULL,

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
    Priority,
    FindingStatus,
    LastVerified
)
VALUES
(
    1,
    1,
    1,
    9.1,
    'Open',
    CURRENT_TIMESTAMP
),
(
    1,
    2,
    2,
    8.8,
    'Open',
    CURRENT_TIMESTAMP
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
),
(
    1,
    2,
    'Executive Summary',
    '2026-10-01',
    '2026-10-31'
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
),
(
    2,
    'Assessment Started',
    'Assessment',
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

    CorrelationType VARCHAR(100),
    
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
    'Version In Range'
),
(
    1,
    2,
    2,
    TRUE,
    'Version In Range'
);

-- Analyst Result
CREATE TABLE AnalystResult
(
    AnalysisResultID SERIAL PRIMARY KEY,

    CorrelationID INT NOT NULL UNIQUE,

    VulnerabilityStatus VARCHAR(30) NOT NULL,

    Confidence VARCHAR(10) NOT NULL,

    ReasoningSummary TEXT,

    SupportingEvidence TEXT[],

    MissingInformation TEXT[],

    Recommendations TEXT[],

    FOREIGN KEY (CorrelationID)
        REFERENCES Correlation(CorrelationID)
        ON DELETE CASCADE,

    CHECK
    (
        VulnerabilityStatus IN
        ('vulnerable', 'unknown', 'not_vulnerable')
    ),

    CHECK
    (
        Confidence IN
        ('HIGH', 'MEDIUM', 'LOW')
    )
);

INSERT INTO AnalystResult
(
    CorrelationID,
    VulnerabilityStatus,
    Confidence,
    ReasoningSummary,
    SupportingEvidence,
    MissingInformation,
    Recommendations
)
VALUES
(
    1,
    'vulnerable',
    'HIGH',
    'Firewall-01 is a Fortinet FortiGate-80F running 7.2.10, which falls inside the affected range 7.2.0 through 7.2.11 for CVE-2025-59718. The asset is public facing, so the FortiCloud SSO login is reachable from the internet.',
    ARRAY['Asset version 7.2.10 falls within the affected range 7.2.0 through 7.2.11.',
          'FortiGate-80F runs FortiOS, the product named in the advisory.',
          'The asset is flagged public facing in the inventory.'],
    ARRAY['Build number of the installed firmware.',
          'Whether FortiCloud SSO is actually enabled on this appliance.'],
    ARRAY['Upgrade FortiOS to 7.2.12 or later.',
          'Restrict administrative access to the management interface.']
),
(
    2,
    'vulnerable',
    'MEDIUM',
    'juanMarquez-Pc reports Google Chrome 97.0.4692.99, below the 98.0.4758.102 fix for CVE-2022-0609. The CVE is listed in the CISA KEV catalog. Confidence is MEDIUM because the version came from a software export rather than the endpoint itself.',
    ARRAY['Installed version 97.0.4692.99 is lower than the fixed version 98.0.4758.102.',
          'CVE-2022-0609 is listed in the CISA KEV catalog.'],
    ARRAY['Date the software export was taken.',
          'Whether Chrome has auto updated since the export.'],
    ARRAY['Update Google Chrome to 98.0.4758.102 or later.',
          'Turn on automatic Chrome updates across the fleet.']
);

--QA Further Review
CREATE TABLE QAFurtherReview
(
    FurtherReviewID SERIAL PRIMARY KEY,

    AnalysisResultID INT NOT NULL UNIQUE,

    Reason TEXT,

    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (AnalysisResultID)
        REFERENCES AnalystResult(AnalysisResultID)
        ON DELETE CASCADE
);

INSERT INTO QAFurtherReview
(
    AnalysisResultID,
    Reason
)
VALUES
(
    1,
    'Analyst confidence is HIGH and the asset is public facing, so an analyst should confirm the installed build before remediation.'
),
(
    2,
    'Analyst confidence is MEDIUM. The Chrome version came from a software export and was not confirmed on the endpoint.'
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
),
(
    2,
    2,
    1
);

