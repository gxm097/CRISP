const express = require('express');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');
const session = require('express-session');                  
const { hashPassword, checkPassword } = require('./createHash');

const { Pool } = require('pg');

const pool = new Pool({
  host: 'localhost',
  port: 5432,
  database: 'crisp',
  user: 'postgres',
  password: 'crisppassword'
});

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.raw({ type: 'multipart/form-data', limit: '10mb' }));

app.use(session({
  secret: 'change-this-to-a-long-random-string',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24
  }
}));


function requireLogin(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/');
  }
}

function requireAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'Account Administrator') {
    next();
  } else {
    res.status(403).json({ message: 'Only administrators can create accounts.' });
  }
}

function getOrganizationId(req) {
  return req.session.user ? req.session.user.organizationId : 1;
}

const importJobs = new Map();

function parseMultipartCsv(req) {
  if (!Buffer.isBuffer(req.body)) return null;
  const contentType = req.headers['content-type'] || '';
  const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
  if (!boundaryMatch) return null;

  const boundary = Buffer.from('--' + (boundaryMatch[1] || boundaryMatch[2]).trim());
  const parts = [];
  let start = req.body.indexOf(boundary);

  while (start !== -1) {
    start += boundary.length;
    if (req.body[start] === 13 && req.body[start + 1] === 10) start += 2;
    const next = req.body.indexOf(boundary, start);
    if (next === -1) break;

    let end = next - 2;
    if (end < start) end = next;
    const part = req.body.subarray(start, end);
    const headerEnd = part.indexOf('\r\n\r\n');
    if (headerEnd === -1) {
      start = next;
      continue;
    }

    const headers = part.subarray(0, headerEnd).toString('utf8');
    const content = part.subarray(headerEnd + 4);
    const nameMatch = headers.match(/name="([^"]+)"/i);
    const filenameMatch = headers.match(/filename="([^"]*)"/i);

      parts.push({
      name: nameMatch ? nameMatch[1] : '',
      filename: filenameMatch ? filenameMatch[1] : null,
      content
    });
    start = next;
  }

  const file = parts.find(part => part.name === 'file' && part.filename);
  if (!file) return null;

  const typePart = parts.find(part => part.name === 'importType');
  return {
    filename: path.basename(file.filename),
    importType: typePart ? typePart.content.toString('utf8').trim() : 'Auto-detect',
    content: file.content
  };
}

function runPython(scriptPath, args = []) {
  return new Promise((resolve, reject) => {
    const pythonCommand = process.env.PYTHON || (process.platform === 'win32' ? 'py' : 'python3');
    const child = spawn(pythonCommand, [scriptPath, ...args], {
      cwd: path.join(__dirname, '..'),
      env: process.env
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk.toString(); });
    child.stderr.on('data', chunk => { stderr += chunk.toString(); });
    child.on('error', reject);
    child.on('close', code => {
      if (code === 0) resolve({ stdout, stderr });
      else reject(new Error(stderr.trim() || stdout.trim() || `Python process exited with ${code}`));
    });
  });
}

app.use('/Styles', express.static(path.join(__dirname, 'Styles')));
app.use('/icons', express.static(path.join(__dirname, 'icons')));
app.use('/src', express.static(path.join(__dirname, 'src')));
app.use('/templates', express.static(path.join(__dirname, 'templates')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const result = await pool.query(
    'SELECT * FROM user_account WHERE username = $1',
    [username]
  );
  const user = result.rows[0];

  if (user && await checkPassword(password, user.password_hash)) {
   
    req.session.user = {
      id: user.user_id,
      username: user.username,
      role: user.role,
      organizationId: user.organization_id
    };
    res.redirect('/overview');
  } else {
    res.redirect('/?error=1');
  }
});


app.get('/dashboard', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/assessments', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'assessments.html'));
});

// one route per page
const pages = ['overview', 'inventory', 'findings', 'reports', 'users', 'settings'];

pages.forEach(page => {
  app.get('/' + page, requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, page + '.html'));
  });
});

app.post('/api/users', requireAdmin, async (req, res) => {
  const { username, email, password, role } = req.body;

  if (!username || !email || !password || !role) {
    return res.status(400).json({ message: 'Fill in every field.' });
  }

  const allowedRoles = ['Account Administrator', 'Analyst'];
  if (!allowedRoles.includes(role)) {
    return res.status(400).json({ message: 'Choose a valid role.' });
  }

  try {
    const hash = await hashPassword(password);

    await pool.query(
      `INSERT INTO user_account (organization_id, username, password_hash, email, role)
       VALUES ($1, $2, $3, $4, $5)`,
      [req.session.user.organizationId, username.trim(), hash, email.trim(), role]
    );

    res.json({ message: `Account created for ${username.trim()}.` });
  } catch (err) {
    if (err.code === '23505') {
      res.status(409).json({ message: 'That username or email is already taken.' });
    } else {
      console.log(err);
      res.status(500).json({ message: 'Something went wrong. Try again.' });
    }
  }
});




app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/api/assets', requireLogin, async (req, res) => {
  const { q = '', type = '', vendor = '' } = req.query;
  const typeNames = { firewall: 'Firewall', switch: 'Switch', ap: 'Access Point' };

  try {
    const result = await pool.query(`
      SELECT a.AssetID AS id,
             a.AssetName AS name,
             t.AssetTypeName AS type,
             a.Vendor AS vendor,
             a.Product AS product,
             a.Version AS version,
             a.Status AS status,
             COUNT(f.FindingID)::int AS findings
      FROM InventoryAsset a
      JOIN AssetType t ON t.AssetTypeID = a.AssetTypeID
      LEFT JOIN Finding f ON f.AssetID = a.AssetID AND f.FindingStatus = 'Open'
      WHERE a.OrganizationID = $1
        AND ($2 = '' OR a.AssetName ILIKE '%' || $2 || '%' OR a.Product ILIKE '%' || $2 || '%')
        AND ($3 = '' OR t.AssetTypeName = $3)
        AND ($4 = '' OR a.Vendor ILIKE $4)
      GROUP BY a.AssetID, t.AssetTypeName
      ORDER BY a.AssetName
    `, [getOrganizationId(req), q, typeNames[type] || '', vendor]);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load assets' });
  }
});

app.get('/api/inventory/summary', requireLogin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT COUNT(*)::int AS total,
             COUNT(*) FILTER (WHERE a.Status = 'Active')::int AS active,
             COUNT(*) FILTER (WHERE EXISTS (
               SELECT 1 FROM Finding f
               WHERE f.AssetID = a.AssetID AND f.FindingStatus = 'Open'
             ))::int AS affected,
             COUNT(*) FILTER (WHERE EXISTS (
               SELECT 1 FROM Finding f
               JOIN Vulnerability v ON v.VulnerabilityID = f.VulnerabilityID
               WHERE f.AssetID = a.AssetID AND f.FindingStatus = 'Open'
                 AND UPPER(v.Severity) IN ('CRITICAL', 'HIGH')
             ))::int AS "needsAttention"
      FROM InventoryAsset a
      WHERE a.OrganizationID = $1
    `, [getOrganizationId(req)]);

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load inventory summary' });
  }
});

app.post('/api/assets', requireLogin, async (req, res) => {
  const { type, status, name, vendor, product, software, public: isPublic } = req.body;

  if (!name || !type) {
    return res.status(400).json({ error: 'Asset name and type are required' });
  }

  try {
    const result = await pool.query(`
      INSERT INTO InventoryAsset
        (OrganizationID, AssetTypeID, AssetName, Vendor, Product, Version, PublicFacing, Status)
      SELECT $1, AssetTypeID, $2, $3, $4, $5, $6, $7
      FROM AssetType
      WHERE AssetTypeName = $8
      RETURNING AssetID AS id
    `, [getOrganizationId(req), name, vendor, product, software, isPublic === 'Yes', status === 'pause' ? 'Paused' : 'Active', type]);

    if (result.rowCount === 0) {
      return res.status(400).json({ error: 'Unknown asset type' });
    }

    res.status(201).json({ id: result.rows[0].id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not save asset' });
  }
});

app.post('/api/assets/import', requireLogin, async (req, res) => {
  const rows = req.body.rows;

  if (!Array.isArray(rows) || rows.length === 0) {
    return res.status(400).json({ errors: ['The file has no rows to import'] });
  }

  const errors = [];
  let added = 0;
  let client;

  try {
    client = await pool.connect();
    await client.query('BEGIN');

    for (let i = 0; i < rows.length; i++) {
      const r = rows[i];
      const rowNumber = i + 1;

      if (!r.name || !r.type) {
        errors.push(`Row ${rowNumber}: name and type are required`);
        continue;
      }

      const result = await client.query(`
        INSERT INTO InventoryAsset
          (OrganizationID, AssetTypeID, AssetName, Vendor, Product, Version, PublicFacing, Status)
        SELECT $1, AssetTypeID, $2, $3, $4, $5, $6, 'Active'
        FROM AssetType
        WHERE LOWER(AssetTypeName) = LOWER($7)
      `, [getOrganizationId(req), r.name, r.vendor || null, r.product || null, r.version || null,
          ['yes', 'true'].includes(String(r.public).toLowerCase()), r.type]);

      if (result.rowCount === 0) {
        errors.push(`Row ${rowNumber}: unknown type "${r.type}"`);
      } else {
        added++;
      }
    }

    if (errors.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ errors });
    }

    await client.query('COMMIT');
    res.json({ added });
  } catch (err) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    console.error(err);
    res.status(500).json({ errors: ['Could not import the file'] });
  } finally {
    if (client) client.release();
  }
});

app.post('/api/import-jobs', requireLogin, async (req, res) => {
  const upload = parseMultipartCsv(req);
  if (!upload) {
    return res.status(422).json({ error: 'CSV file and import type are required', errors: ['The upload must include a CSV file'] });
  }
  if (!upload.filename.toLowerCase().endsWith('.csv')) {
    return res.status(422).json({ error: 'Unsupported file type', errors: ['Only CSV files are supported'] });
  }
  if (upload.content.length === 0) {
    return res.status(422).json({ error: 'The CSV file is empty', errors: ['The file has no data'] });
  }

  const jobId = crypto.randomUUID();
  const uploadDir = fs.mkdtempSync(path.join(os.tmpdir(), 'crisp-import-'));
  const inputPath = path.join(uploadDir, upload.filename);
  fs.writeFileSync(inputPath, upload.content);

  const job = {
    jobId,
    status: 'Queued',
    stage: 'Uploading',
    progress: 0,
    assessmentId: null,
    filename: upload.filename,
    importType: upload.importType,
    summary: null,
    errors: [],
    warnings: []
  };
  importJobs.set(jobId, job);

  res.status(202).json(job);

  (async () => {
    try {
      job.status = 'Running';
      job.stage = 'Cleaning';
      job.progress = 20;

      const root = path.join(__dirname, '..');
      const outputPath = path.join(uploadDir, upload.filename.replace(/\.csv$/i, '') + '_inventory.sql');
      // Firewall exports have a "Controller Counter" column, so Auto-detect can spot them
      const firstLine = upload.content.toString('utf8').split(/\r?\n/)[0].toLowerCase();
      const isFirewallFile = upload.importType === 'Firewall inventory'
        || (upload.importType === 'Auto-detect' && firstLine.includes('controller counter'));

      const cleaner = isFirewallFile
        ? path.join(root, 'cleaners', 'firewallClean.py')
        : path.join(root, 'cleaners', 'generalClean.py');

      await runPython(cleaner, ['--input', inputPath, '--output', outputPath]);

      job.stage = 'Loading inventory';
      job.progress = 45;
      await runPython(path.join(root, 'cleaners', 'loadInventory.py'), [
        outputPath,
        '--docker',
        '--force',
        '--user-id', String(req.session.user?.id || 1)
      ]);

      /* job.stage = 'Researching';
      job.progress = 65;
      await runPython(path.join(root, 'agents', 'research', 'buildResearchSummary.py'));
      await runPython(path.join(root, 'agents', 'research', 'researchAgent.py'));

      job.stage = 'Correlating';
      job.progress = 80;
      await runPython(path.join(root, 'agents', 'reports', 'correlationCOPY.py'));

      job.stage = 'Analyzing';
      job.progress = 90;
      await runPython(path.join(root, 'agents', 'analyzerAgent.py'));

      const assessment = await pool.query(`
        SELECT AssessmentID
        FROM Assessment
        WHERE OrganizationID = $1
        ORDER BY AssessmentID DESC
        LIMIT 1
      `, [getOrganizationId(req)]);

      job.assessmentId = assessment.rows[0]?.assessmentid || null; */

      // Import only adds the assets. Research runs when someone clicks Run assessment.

      job.status = 'Completed';
      job.stage = 'Completed';
      job.progress = 100;
      job.summary = { filename: upload.filename, importType: upload.importType };
    } catch (error) {
      job.status = 'Failed';
      job.stage = 'Failed';
      job.errors = [error.message];
    } finally {
      fs.rmSync(uploadDir, { recursive: true, force: true });
    }
  })();
});

app.get('/api/import-jobs/:jobId', requireLogin, (req, res) => {
  const job = importJobs.get(req.params.jobId);
  if (!job) {
    return res.status(404).json({ message: 'Import job not found.' });
  }
  res.json(job);
});

app.get('/api/dashboard', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const [assetResult, findingResult, priorityResult, assessmentResult,
           criticalResult, postureResult, latestRunResult, nextRunResult] = await Promise.all([
      pool.query('SELECT COUNT(*)::int AS count FROM InventoryAsset WHERE OrganizationID = $1', [organizationId]),
      pool.query(`SELECT COUNT(*)::int AS count FROM Finding f JOIN InventoryAsset a ON a.AssetID = f.AssetID
                  WHERE a.OrganizationID = $1 AND f.FindingStatus = 'Open'`, [organizationId]),
      pool.query(`SELECT v.CVE AS cve, a.AssetName AS asset, v.CVSSScore::float AS cvss,
                         v.Severity AS severity, f.FindingStatus AS status, f.FirstDetected AS discovered
                  FROM Finding f
                  JOIN InventoryAsset a ON a.AssetID = f.AssetID
                  JOIN Vulnerability v ON v.VulnerabilityID = f.VulnerabilityID
                  WHERE f.OrganizationID = $1 AND f.FindingStatus = 'Open'
                  ORDER BY v.CVSSScore DESC NULLS LAST, f.FirstDetected DESC
                  LIMIT 10`, [organizationId]),
      pool.query(`SELECT AssessmentID, AssessmentStart, AssessmentEnd, TriggerType, Status
                  FROM Assessment WHERE OrganizationID = $1 ORDER BY AssessmentID DESC LIMIT 1`, [organizationId]),

      // open findings with Critical severity
      pool.query(`SELECT COUNT(*)::int AS count
                  FROM Finding f JOIN Vulnerability v ON v.VulnerabilityID = f.VulnerabilityID
                  WHERE f.OrganizationID = $1 AND f.FindingStatus = 'Open'
                    AND UPPER(v.Severity) = 'CRITICAL'`, [organizationId]),

      // active assets, and how many of them have an open Critical or High finding
      pool.query(`SELECT COUNT(*)::int AS active,
                         COUNT(*) FILTER (WHERE EXISTS (
                           SELECT 1 FROM Finding f
                           JOIN Vulnerability v ON v.VulnerabilityID = f.VulnerabilityID
                           WHERE f.AssetID = a.AssetID AND f.FindingStatus = 'Open'
                             AND UPPER(v.Severity) IN ('CRITICAL', 'HIGH')
                         ))::int AS "atRisk"
                  FROM InventoryAsset a
                  WHERE a.OrganizationID = $1 AND a.Status = 'Active'`, [organizationId]),

      // latest completed assessment run
      pool.query(`SELECT a.AssessmentEnd AS "completedAt",
                         ROUND(EXTRACT(EPOCH FROM (a.AssessmentEnd - a.AssessmentStart)) / 60)::int AS "durationMinutes",
                         (SELECT COUNT(*)::int FROM AssessmentAsset aa WHERE aa.AssessmentID = a.AssessmentID) AS "assetsAssessed",
                         (SELECT COUNT(*)::int FROM Finding f
                          WHERE f.OrganizationID = a.OrganizationID
                            AND f.FirstDetected BETWEEN a.AssessmentStart AND a.AssessmentEnd) AS "newFindings"
                  FROM Assessment a
                  WHERE a.OrganizationID = $1 AND a.Status = 'Completed'
                  ORDER BY a.AssessmentEnd DESC
                  LIMIT 1`, [organizationId]),

      // next enabled scheduled run
      pool.query(`SELECT MIN(NextRun) AS "nextRun"
                  FROM AssessmentSchedule
                  WHERE OrganizationID = $1 AND Enabled = TRUE AND NextRun > CURRENT_TIMESTAMP`, [organizationId])
    ]);

    const { active, atRisk } = postureResult.rows[0];

    res.json({
      assets: assetResult.rows[0].count,
      findings: findingResult.rows[0].count,
      priorityFindings: priorityResult.rows,
      assessment: assessmentResult.rows[0] || null,
      critical: criticalResult.rows[0].count,
      // % of active assets with no open Critical or High finding
      posture: active > 0 ? Math.round(100 * (active - atRisk) / active) : null,
      activeAssets: active,
      latestRun: latestRunResult.rows[0] || null,
      nextRun: nextRunResult.rows[0].nextRun
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load dashboard' });
  }
});


app.get('/api/assessments/snapshot', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const [scheduleResult, assessmentResult, assetResult, sourceResult, researchResult, assessmentAssetResult, correlationResult, analystResult] = await Promise.all([
      pool.query(`SELECT ScheduleID, Frequency, Enabled, LastRun, NextRun FROM AssessmentSchedule WHERE OrganizationID = $1 ORDER BY ScheduleID`, [organizationId]),
      pool.query(`SELECT AssessmentID, AssessmentStart, AssessmentEnd, TriggerType, Status FROM Assessment WHERE OrganizationID = $1 ORDER BY AssessmentID DESC`, [organizationId]),
      pool.query(`SELECT a.AssetID, a.AssetTypeID, a.AssetName, a.Version, a.Status FROM InventoryAsset a WHERE a.OrganizationID = $1 ORDER BY a.AssetID`, [organizationId]),
      pool.query('SELECT SourceID, SourceName, SourceType, Enabled FROM VulnerabilitySource ORDER BY SourceID'),
      pool.query(`SELECT r.ResearchResultID, r.AssessmentID, r.SourceID, r.AssetID, r.QueryText, r.RetrievedAt, r.Status, r.RawContent, r.SourceURL
                  FROM ResearchResult r JOIN Assessment a ON a.AssessmentID = r.AssessmentID
                  WHERE a.OrganizationID = $1 ORDER BY r.ResearchResultID DESC`, [organizationId]),
      pool.query(`SELECT aa.AssessmentID, aa.AssetID, aa.AssetSnapshotVersion, aa.EvaluationStatus
                  FROM AssessmentAsset aa JOIN Assessment a ON a.AssessmentID = aa.AssessmentID
                  WHERE a.OrganizationID = $1`, [organizationId]),
      pool.query(`SELECT c.CorrelationID, c.AssessmentID, c.AssetID, c.VulnerabilityID, c.PotentiallyVulnerable, c.CorrelationType
                  FROM Correlation c JOIN Assessment a ON a.AssessmentID = c.AssessmentID
                  WHERE a.OrganizationID = $1`, [organizationId]),
      pool.query(`SELECT ar.AnalysisResultID, ar.CorrelationID, ar.VulnerabilityStatus, ar.Confidence, ar.ReasoningSummary,
                         ar.SupportingEvidence, ar.MissingInformation, ar.Recommendations
                  FROM AnalystResult ar JOIN Correlation c ON c.CorrelationID = ar.CorrelationID
                  JOIN Assessment a ON a.AssessmentID = c.AssessmentID
                  WHERE a.OrganizationID = $1`, [organizationId])
    ]);

    const assessments = assessmentResult.rows.map(row => ({
      AssessmentID: row.assessmentid,
      AssessmentName: row.triggerType === 'Manual' ? 'Manual assessment' : 'Scheduled assessment',
      AssessmentStart: row.assessmentstart,
      AssessmentEnd: row.assessmentend,
      TriggerType: row.triggertype,
      Status: row.status
    }));

    const schedules = scheduleResult.rows.map(row => ({
      ScheduleID: row.scheduleid,
      AssessmentName: `Assessment schedule ${row.scheduleid}`,
      Frequency: row.frequency,
      CustomIntervalDays: null,
      CustomIntervalHours: null,
      AssetScope: 'All active assets',
      StartAt: row.nextrun,
      NextRun: row.nextrun,
      TimeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      Enabled: row.enabled,
      LastRun: row.lastrun
    }));

    res.json({
      schedules,
      assessments,
      assessmentAssets: assessmentAssetResult.rows.map(row => ({ AssessmentID: row.assessmentid, AssetID: row.assetid, AssetSnapshotVersion: row.assetsnapshotversion, EvaluationStatus: row.evaluationstatus })),
      researchResults: researchResult.rows.map(row => ({ ResearchResultID: row.researchresultid, AssessmentID: row.assessmentid, SourceID: row.sourceid, AssetID: row.assetid, QueryText: row.querytext, RetrievedAt: row.retrievedat, Status: row.status, RawContent: row.rawcontent, SourceURL: row.sourceurl })),
      assets: assetResult.rows.map(row => ({ AssetID: row.assetid, AssetTypeID: row.assettypeid, AssetName: row.assetname, Version: row.version, Status: row.status })),
      sources: sourceResult.rows.map(row => ({ SourceID: row.sourceid, SourceName: row.sourcename, SourceType: row.sourcetype, Enabled: row.enabled })),
      correlations: correlationResult.rows.map(row => ({ CorrelationID: row.correlationid, AssessmentID: row.assessmentid, AssetID: row.assetid, VulnerabilityID: row.vulnerabilityid, PotentiallyVulnerable: row.potentiallyvulnerable, CorrelationType: row.correlationtype })),
      analystResults: analystResult.rows.map(row => ({ AnalysisResultID: row.analysisresultid, CorrelationID: row.correlationid, VulnerabilityStatus: row.vulnerabilitystatus, Confidence: row.confidence, ReasoningSummary: row.reasoningsummary, SupportingEvidence: row.supportingevidence, MissingInformation: row.missinginformation, Recommendations: row.recommendations }))
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load assessments' });
  }
});

app.post('/api/assessments', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  const active = await pool.query(`SELECT COUNT(*)::int AS count FROM InventoryAsset WHERE OrganizationID = $1 AND Status = 'Active'`, [organizationId]);
  if (active.rows[0].count === 0) return res.status(422).json({ message: 'Add at least one active inventory asset first.' });

  const source = await pool.query('SELECT COUNT(*)::int AS count FROM VulnerabilitySource WHERE Enabled = TRUE');
  if (source.rows[0].count === 0) return res.status(422).json({ message: 'Enable an approved intelligence source first.' });

  const running = await pool.query(`SELECT AssessmentID FROM Assessment WHERE OrganizationID = $1 AND Status IN ('Pending', 'Running') LIMIT 1`, [organizationId]);
  if (running.rows.length > 0) return res.status(409).json({ message: 'An assessment is already pending or running.' });

  const result = await pool.query(`INSERT INTO Assessment (OrganizationID, AssessmentStart, TriggerType, Status)
                                   VALUES ($1, CURRENT_TIMESTAMP, 'Manual', 'Running') RETURNING AssessmentID`, [organizationId]);
  const assessmentId = result.rows[0].assessmentid;
  res.status(202).json({ assessmentId, status: 'Running' });

  (async () => {
    try {
      const root = path.join(__dirname, '..');
      await runPython(path.join(root, 'agents', 'research', 'buildResearchSummary.py'));
      await runPython(path.join(root, 'agents', 'research', 'researchAgent.py'));
      await runPython(path.join(root, 'agents', 'reports', 'correlationCOPY.py'), ['--assessment', String(assessmentId)]);
      await runPython(path.join(root, 'agents', 'analyzerAgent.py'));
      await pool.query(`UPDATE Assessment SET AssessmentEnd = CURRENT_TIMESTAMP, Status = 'Completed' WHERE AssessmentID = $1 AND OrganizationID = $2`, [assessmentId, organizationId]);
    } catch (error) {
      await pool.query(`UPDATE Assessment SET AssessmentEnd = CURRENT_TIMESTAMP, Status = 'Failed' WHERE AssessmentID = $1 AND OrganizationID = $2`, [assessmentId, organizationId]);
    }
  })();
});

app.get('/api/assessments/:id', requireLogin, async (req, res) => {
  const { id } = req.params;
  try {
    const assessment = await pool.query(`
      SELECT a.AssessmentID, a.TriggerType, a.Status, a.AssessmentStart, a.AssessmentEnd, a.Frequency,
             ARRAY_AGG(DISTINCT aa.AssetID) AS assets,
             COUNT(DISTINCT f.FindingID) FILTER (WHERE f.FindingStatus = 'Open') AS openFindings,
             COUNT(DISTINCT f.FindingID) FILTER (WHERE f.FindingStatus = 'Closed') AS closedFindings
      FROM Assessment a
      JOIN AssessmentAsset aa ON aa.AssessmentID = a.AssessmentID
      LEFT JOIN Finding f ON f.AssetID = aa.AssetID
      WHERE a.AssessmentID = $1
      GROUP BY a.AssessmentID
    `, [id]);

    if (assessment.rows.length === 0) {
      return res.status(404).json({ error: 'Assessment not found' });
    }

    res.json(assessment.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load assessment' });
  }
});

app.post('/api/assessments/:id/restart', requireLogin, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(`
      UPDATE Assessment
      SET Status = 'Scheduled', AssessmentStart = NOW(), AssessmentEnd = NOW()
      WHERE AssessmentID = $1
    `, [id]);

    await pool.query(`
      UPDATE AssessmentAsset
      SET EvaluationStatus = 'Not started'
      WHERE AssessmentID = $1
    `, [id]);

    res.json({ message: 'Assessment restarted' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not restart assessment' });
  }
});

app.post('/api/assessments/:id/stop', requireLogin, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(`
      UPDATE Assessment
      SET Status = 'Stopped'
      WHERE AssessmentID = $1
    `, [id]);

    res.json({ message: 'Assessment stopped' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not stop assessment' });
  }
});

app.get('/api/research-results/:id', requireLogin, async (req, res) => {
  const { id } = req.params;
  try {
    const results = await pool.query(`
      SELECT r.ResearchResultID, r.QueryText, r.RetrievedAt, r.Status, r.RawContent, r.SourceURL,
             a.AssetName, a.AssetID, a.Version, a.Status AS AssetStatus,
             v.CVE, v.CVSSScore, v.Severity
      FROM ResearchResult r
      JOIN InventoryAsset a ON a.AssetID = r.AssetID
      LEFT JOIN Vulnerability v ON v.VulnerabilityID = r.VulnerabilityID
      WHERE r.AssessmentID = $1
      ORDER BY r.RetrievedAt DESC
    `, [id]);

    res.json(results.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load research results' });
  }
});

app.get('/api/asset-types', requireLogin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM AssetType ORDER BY AssetTypeName');
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load asset types' });
  }
});

app.get('/api/vulnerabilities', requireLogin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM Vulnerability ORDER BY CVSSScore DESC');
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load vulnerabilities' });
  }
});

app.get('/api/findings', requireLogin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT f.FindingID AS id,
             v.CVE AS cve,
             v.Title AS title,
             a.AssetName AS asset,
             t.AssetTypeName AS "assetType",
             v.CVSSScore::float AS cvss,
             v.Severity AS severity,
             v.KEVFlag AS kev,
             f.FindingStatus AS status,
             TO_CHAR(f.FirstDetected, 'YYYY-MM-DD') AS "firstDetected"
      FROM Finding f
      JOIN InventoryAsset a ON a.AssetID = f.AssetID
      JOIN AssetType t ON t.AssetTypeID = a.AssetTypeID
      JOIN Vulnerability v ON v.VulnerabilityID = f.VulnerabilityID
      WHERE f.OrganizationID = $1
      ORDER BY v.CVSSScore DESC NULLS LAST, f.FirstDetected DESC
    `, [getOrganizationId(req)]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load findings' });
  }
});

app.get('/api/notifications', requireLogin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT n.NotificationID, n.Message, n.Status, n.CreatedAt, n.ReadAt,
             a.AssetName, a.AssetID, a.Version, a.Status AS AssetStatus,
             v.CVE, v.CVSSScore, v.Severity
      FROM Notification n
      LEFT JOIN InventoryAsset a ON a.AssetID = n.AssetID
      LEFT JOIN Vulnerability v ON v.VulnerabilityID = n.VulnerabilityID
      WHERE n.OrganizationID = $1
      ORDER BY n.CreatedAt DESC
    `, [getOrganizationId(req)]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load notifications' });
  }
});

app.post('/api/notifications/:id/read', requireLogin, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(`
      UPDATE Notification
      SET Status = 'Read', ReadAt = NOW()
      WHERE NotificationID = $1
    `, [id]);

    res.json({ message: 'Notification marked as read' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not update notification' });
  }
});

app.get('/api/settings', requireLogin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM OrganizationSettings WHERE OrganizationID = $1', [getOrganizationId(req)]);
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load settings' });
  }
});

app.post('/api/settings', requireLogin, async (req, res) => {
  const { key, value } = req.body;
  try {
    await pool.query(`
      INSERT INTO OrganizationSettings (OrganizationID, SettingKey, SettingValue)
      VALUES ($1, $2, $3)
      ON CONFLICT (OrganizationID, SettingKey) DO UPDATE SET SettingValue = $3
    `, [getOrganizationId(req), key, value]);

    res.json({ message: 'Settings updated' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not update settings' });
  }
});

app.get('/api/users/me', requireLogin, (req, res) => {
  res.json(req.session.user);
});

app.post('/api/users/me/password', requireLogin, async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;

  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.status(400).json({ message: 'Fill in every field.' });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ message: 'The new passwords do not match.' });
  }

  try {
    const result = await pool.query(
      'SELECT password_hash FROM user_account WHERE user_id = $1',
      [req.session.user.id]
    );
    const user = result.rows[0];

    if (!user || !await checkPassword(currentPassword, user.password_hash)) {
      return res.status(401).json({ message: 'Your current password is wrong.' });
    }

    const hash = await hashPassword(newPassword);

    await pool.query(
      'UPDATE user_account SET password_hash = $1 WHERE user_id = $2',
      [hash, req.session.user.id]
    );

    res.json({ message: 'Password changed.' });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: 'Something went wrong. Try again.' });
  }
});

app.get('/api/users', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM user_account WHERE organization_id = $1', [req.session.user.organizationId]);
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load users' });
  }
});

app.get('/api/users/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM user_account WHERE user_id = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load user' });
  }
});

app.put('/api/users/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { username, email, password, role } = req.body;

  if (!username || !email || !role) {
    return res.status(400).json({ message: 'Username, email, and role are required' });
  }

  const allowedRoles = ['Account Administrator', 'Analyst'];
  if (!allowedRoles.includes(role)) {
    return res.status(400).json({ message: 'Choose a valid role' });
  }

  try {
    const updates = [];
    const values = [username, email, role, id];

    if (password) {
      const hash = await hashPassword(password);
      updates.push('password_hash = $4');
      values.push(hash);
    }

    await pool.query(`
      UPDATE user_account
      SET username = $1, email = $2, role = $3, ${updates.join(', ')}
      WHERE user_id = $4
    `, values);

    res.json({ message: 'User updated' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not update user' });
  }
});

app.delete('/api/users/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM user_account WHERE user_id = $1', [id]);
    res.json({ message: 'User deleted' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not delete user' });
  }
});

app.get('/api/reports/asset-summary', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT a.AssetID, a.AssetName, a.Vendor, a.Product, a.Version, a.Status,
             COUNT(f.FindingID) FILTER (WHERE f.FindingStatus = 'Open') AS openFindings,
             COUNT(f.FindingID) FILTER (WHERE f.FindingStatus = 'Closed') AS closedFindings
      FROM InventoryAsset a
      LEFT JOIN Finding f ON f.AssetID = a.AssetID
      WHERE a.OrganizationID = $1
      GROUP BY a.AssetID
      ORDER BY a.AssetName
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load asset summary' });
  }
});

app.get('/api/reports/vulnerability-summary', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT v.VulnerabilityID, v.CVE, v.CVSSScore, v.Severity,
             COUNT(f.FindingID) FILTER (WHERE f.FindingStatus = 'Open') AS openFindings,
             COUNT(f.FindingID) FILTER (WHERE f.FindingStatus = 'Closed') AS closedFindings
      FROM Vulnerability v
      LEFT JOIN Finding f ON f.VulnerabilityID = v.VulnerabilityID
      WHERE v.OrganizationID = $1
      GROUP BY v.VulnerabilityID
      ORDER BY v.CVSSScore DESC NULLS LAST
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load vulnerability summary' });
  }
});

app.get('/api/reports/asset-findings', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT a.AssetID, a.AssetName, a.Vendor, a.Product, a.Version, a.Status,
             f.FindingID, f.CVE, f.CVSSScore, f.Severity, f.FindingStatus
      FROM InventoryAsset a
      JOIN Finding f ON f.AssetID = a.AssetID
      WHERE a.OrganizationID = $1
      ORDER BY a.AssetName, f.CVSSScore DESC NULLS LAST
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load asset findings' });
  }
});

app.get('/api/reports/vulnerability-findings', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT v.VulnerabilityID, v.CVE, v.CVSSScore, v.Severity,
             f.FindingID, f.AssetID, f.FindingStatus
      FROM Vulnerability v
      JOIN Finding f ON f.VulnerabilityID = v.VulnerabilityID
      WHERE v.OrganizationID = $1
      ORDER BY v.CVSSScore DESC NULLS LAST
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load vulnerability findings' });
  }
});

app.get('/api/reports/asset-research', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT a.AssetID, a.AssetName, a.Vendor, a.Product, a.Version, a.Status,
             r.ResearchResultID, r.QueryText, r.RetrievedAt, r.Status AS ResearchStatus
      FROM InventoryAsset a
      JOIN ResearchResult r ON r.AssetID = a.AssetID
      WHERE a.OrganizationID = $1
      ORDER BY a.AssetName, r.RetrievedAt DESC
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load asset research' });
  }
});

app.get('/api/reports/vulnerability-research', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT v.VulnerabilityID, v.CVE, v.CVSSScore, v.Severity,
             r.ResearchResultID, r.QueryText, r.RetrievedAt, r.Status AS ResearchStatus
      FROM Vulnerability v
      JOIN ResearchResult r ON r.VulnerabilityID = v.VulnerabilityID
      WHERE v.OrganizationID = $1
      ORDER BY v.CVSSScore DESC NULLS LAST, r.RetrievedAt DESC
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load vulnerability research' });
  }
});

app.get('/api/reports/asset-correlation', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT a.AssetID, a.AssetName, a.Vendor, a.Product, a.Version, a.Status,
             c.CorrelationID, c.PotentiallyVulnerable, c.CorrelationType
      FROM InventoryAsset a
      JOIN Correlation c ON c.AssetID = a.AssetID
      WHERE a.OrganizationID = $1
      ORDER BY a.AssetName, c.CorrelationType
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load asset correlation' });
  }
});

app.get('/api/reports/vulnerability-correlation', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT v.VulnerabilityID, v.CVE, v.CVSSScore, v.Severity,
             c.CorrelationID, c.PotentiallyVulnerable, c.CorrelationType
      FROM Vulnerability v
      JOIN Correlation c ON c.VulnerabilityID = v.VulnerabilityID
      WHERE v.OrganizationID = $1
      ORDER BY v.CVSSScore DESC NULLS LAST, c.CorrelationType
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load vulnerability correlation' });
  }
});

app.get('/api/reports/asset-evidence', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT a.AssetID, a.AssetName, a.Vendor, a.Product, a.Version, a.Status,
             e.EvidenceID, e.Description, e.FilePath, e.UploadedAt
      FROM InventoryAsset a
      JOIN Evidence e ON e.AssetID = a.AssetID
      WHERE a.OrganizationID = $1
      ORDER BY a.AssetName, e.UploadedAt DESC
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load asset evidence' });
  }
});

app.get('/api/reports/vulnerability-evidence', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT v.VulnerabilityID, v.CVE, v.CVSSScore, v.Severity,
             e.EvidenceID, e.Description, e.FilePath, e.UploadedAt
      FROM Vulnerability v
      JOIN Evidence e ON e.VulnerabilityID = v.VulnerabilityID
      WHERE v.OrganizationID = $1
      ORDER BY v.CVSSScore DESC NULLS LAST, e.UploadedAt DESC
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load vulnerability evidence' });
  }
});

app.get('/api/reports/asset-notes', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT a.AssetID, a.AssetName, a.Vendor, a.Product, a.Version, a.Status,
             n.NoteID, n.Content, n.CreatedAt
      FROM InventoryAsset a
      JOIN Note n ON n.AssetID = a.AssetID
      WHERE a.OrganizationID = $1
      ORDER BY a.AssetName, n.CreatedAt DESC
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load asset notes' });
  }
});

app.get('/api/reports/vulnerability-notes', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT v.VulnerabilityID, v.CVE, v.CVSSScore, v.Severity,
             n.NoteID, n.Content, n.CreatedAt
      FROM Vulnerability v
      JOIN Note n ON n.VulnerabilityID = v.VulnerabilityID
      WHERE v.OrganizationID = $1
      ORDER BY v.CVSSScore DESC NULLS LAST, n.CreatedAt DESC
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load vulnerability notes' });
  }
});

app.get('/api/reports/asset-tasks', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT a.AssetID, a.AssetName, a.Vendor, a.Product, a.Version, a.Status,
             t.TaskID, t.Description, t.DueDate, t.Status AS TaskStatus
      FROM InventoryAsset a
      JOIN Task t ON t.AssetID = a.AssetID
      WHERE a.OrganizationID = $1
      ORDER BY a.AssetName, t.DueDate
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load asset tasks' });
  }
});

app.get('/api/reports/vulnerability-tasks', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT v.VulnerabilityID, v.CVE, v.CVSSScore, v.Severity,
             t.TaskID, t.Description, t.DueDate, t.Status AS TaskStatus
      FROM Vulnerability v
      JOIN Task t ON t.VulnerabilityID = v.VulnerabilityID
      WHERE v.OrganizationID = $1
      ORDER BY v.CVSSScore DESC NULLS LAST, t.DueDate
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load vulnerability tasks' });
  }
});

app.get('/api/reports/asset-history', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT a.AssetID, a.AssetName, a.Vendor, a.Product, a.Version, a.Status,
             h.ChangeID, h.ChangeType, h.ChangedAt, h.Notes
      FROM InventoryAsset a
      JOIN AssetHistory h ON h.AssetID = a.AssetID
      WHERE a.OrganizationID = $1
      ORDER BY a.AssetName, h.ChangedAt DESC
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load asset history' });
  }
});

app.get('/api/reports/vulnerability-history', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT v.VulnerabilityID, v.CVE, v.CVSSScore, v.Severity,
             h.ChangeID, h.ChangeType, h.ChangedAt, h.Notes
      FROM Vulnerability v
      JOIN VulnerabilityHistory h ON h.VulnerabilityID = v.VulnerabilityID
      WHERE v.OrganizationID = $1
      ORDER BY v.CVSSScore DESC NULLS LAST, h.ChangedAt DESC
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load vulnerability history' });
  }
});

app.get('/api/reports/asset-imports', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT a.AssetID, a.AssetName, a.Vendor, a.Product, a.Version, a.Status,
             i.ImportID, i.FileName, i.ImportedAt, i.Status AS ImportStatus
      FROM InventoryAsset a
      JOIN AssetImport i ON i.AssetID = a.AssetID
      WHERE a.OrganizationID = $1
      ORDER BY a.AssetName, i.ImportedAt DESC
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load asset imports' });
  }
});

app.get('/api/reports/vulnerability-imports', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT v.VulnerabilityID, v.CVE, v.CVSSScore, v.Severity,
             i.ImportID, i.FileName, i.ImportedAt, i.Status AS ImportStatus
      FROM Vulnerability v
      JOIN VulnerabilityImport i ON i.VulnerabilityID = v.VulnerabilityID
      WHERE v.OrganizationID = $1
      ORDER BY v.CVSSScore DESC NULLS LAST, i.ImportedAt DESC
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load vulnerability imports' });
  }
});

app.get('/api/reports/asset-exports', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT a.AssetID, a.AssetName, a.Vendor, a.Product, a.Version, a.Status,
             e.ExportID, e.FileName, e.ExportedAt, e.Status AS ExportStatus
      FROM InventoryAsset a
      JOIN AssetExport e ON e.AssetID = a.AssetID
      WHERE a.OrganizationID = $1
      ORDER BY a.AssetName, e.ExportedAt DESC
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load asset exports' });
  }
});

app.get('/api/reports/vulnerability-exports', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT v.VulnerabilityID, v.CVE, v.CVSSScore, v.Severity,
             e.ExportID, e.FileName, e.ExportedAt, e.Status AS ExportStatus
      FROM Vulnerability v
      JOIN VulnerabilityExport e ON e.VulnerabilityID = v.VulnerabilityID
      WHERE v.OrganizationID = $1
      ORDER BY v.CVSSScore DESC NULLS LAST, e.ExportedAt DESC
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load vulnerability exports' });
  }
});

app.get('/api/reports/asset-templates', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT a.AssetID, a.AssetName, a.Vendor, a.Product, a.Version, a.Status,
             t.TemplateID, t.FileName, t.CreatedAt, t.Status AS TemplateStatus
      FROM InventoryAsset a
      JOIN AssetTemplate t ON t.AssetID = a.AssetID
      WHERE a.OrganizationID = $1
      ORDER BY a.AssetName, t.CreatedAt DESC
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load asset templates' });
  }
});

app.get('/api/reports/vulnerability-templates', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT v.VulnerabilityID, v.CVE, v.CVSSScore, v.Severity,
             t.TemplateID, t.FileName, t.CreatedAt, t.Status AS TemplateStatus
      FROM Vulnerability v
      JOIN VulnerabilityTemplate t ON t.VulnerabilityID = v.VulnerabilityID
      WHERE v.OrganizationID = $1
      ORDER BY v.CVSSScore DESC NULLS LAST, t.CreatedAt DESC
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load vulnerability templates' });
  }
});

app.get('/api/reports/asset-schedules', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT a.AssetID, a.AssetName, a.Vendor, a.Product, a.Version, a.Status,
             s.ScheduleID, s.Frequency, s.Enabled, s.LastRun, s.NextRun
      FROM InventoryAsset a
      JOIN AssessmentSchedule s ON s.AssetID = a.AssetID
      WHERE a.OrganizationID = $1
      ORDER BY a.AssetName, s.NextRun
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load asset schedules' });
  }
});

app.get('/api/reports/vulnerability-schedules', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT v.VulnerabilityID, v.CVE, v.CVSSScore, v.Severity,
             s.ScheduleID, s.Frequency, s.Enabled, s.LastRun, s.NextRun
      FROM Vulnerability v
      JOIN AssessmentSchedule s ON s.VulnerabilityID = v.VulnerabilityID
      WHERE v.OrganizationID = $1
      ORDER BY v.CVSSScore DESC NULLS LAST, s.NextRun
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load vulnerability schedules' });
  }
});

app.get('/api/reports/asset-owners', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT a.AssetID, a.AssetName, a.Vendor, a.Product, a.Version, a.Status,
             o.OwnerID, o.OwnerName, o.Contact, o.Email
      FROM InventoryAsset a
      JOIN AssetOwner o ON o.AssetID = a.AssetID
      WHERE a.OrganizationID = $1
      ORDER BY a.AssetName, o.OwnerName
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load asset owners' });
  }
});

app.get('/api/reports/vulnerability-owners', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT v.VulnerabilityID, v.CVE, v.CVSSScore, v.Severity,
             o.OwnerID, o.OwnerName, o.Contact, o.Email
      FROM Vulnerability v
      JOIN VulnerabilityOwner o ON o.VulnerabilityID = v.VulnerabilityID
      WHERE v.OrganizationID = $1
      ORDER BY v.CVSSScore DESC NULLS LAST, o.OwnerName
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load vulnerability owners' });
  }
});

app.get('/api/reports/asset-contacts', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT a.AssetID, a.AssetName, a.Vendor, a.Product, a.Version, a.Status,
             c.ContactID, c.ContactName, c.Phone, c.Email
      FROM InventoryAsset a
      JOIN AssetContact c ON c.AssetID = a.AssetID
      WHERE a.OrganizationID = $1
      ORDER BY a.AssetName, c.ContactName
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load asset contacts' });
  }
});

app.get('/api/reports/vulnerability-contacts', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT v.VulnerabilityID, v.CVE, v.CVSSScore, v.Severity,
             c.ContactID, c.ContactName, c.Phone, c.Email
      FROM Vulnerability v
      JOIN VulnerabilityContact c ON c.VulnerabilityID = v.VulnerabilityID
      WHERE v.OrganizationID = $1
      ORDER BY v.CVSSScore DESC NULLS LAST, c.ContactName
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load vulnerability contacts' });
  }
});

app.get('/api/reports/asset-exposures', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT a.AssetID, a.AssetName, a.Vendor, a.Product, a.Version, a.Status,
             e.ExposureID, e.Description, e.Level, e.Status AS ExposureStatus
      FROM InventoryAsset a
      JOIN AssetExposure e ON e.AssetID = a.AssetID
      WHERE a.OrganizationID = $1
      ORDER BY a.AssetName, e.Level DESC NULLS LAST
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load asset exposures' });
  }
});

app.get('/api/reports/vulnerability-exposures', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  try {
    const result = await pool.query(`
      SELECT v.VulnerabilityID, v.CVE, v.CVSSScore, v.Severity,
             e.ExposureID, e.Description, e.Level, e.Status AS ExposureStatus
      FROM Vulnerability v
      JOIN VulnerabilityExposure e ON e.VulnerabilityID = v.VulnerabilityID
      WHERE v.OrganizationID = $1
      ORDER BY v.CVSSScore DESC NULLS LAST, e.Level DESC NULLS LAST
    `, [organizationId]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load vulnerability exposures' });
  }
});

app.post('/api/assessment-schedules', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  const start = req.body.StartAt ? new Date(req.body.StartAt) : null;
  if (!req.body.Frequency) return res.status(422).json({ message: 'Frequency is required.' });
  const result = await pool.query(`INSERT INTO AssessmentSchedule (OrganizationID, Frequency, Enabled, NextRun)
                                   VALUES ($1, $2, $3, $4) RETURNING ScheduleID`,
    [organizationId, req.body.Frequency, req.body.Enabled !== false, start]);
  res.status(201).json({ scheduleId: result.rows[0].scheduleid });
});

app.put('/api/assessment-schedules/:id', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  const start = req.body.StartAt ? new Date(req.body.StartAt) : null;
  const result = await pool.query(`UPDATE AssessmentSchedule SET Frequency = $1, Enabled = $2, NextRun = $3
                                   WHERE ScheduleID = $4 AND OrganizationID = $5`,
    [req.body.Frequency, req.body.Enabled !== false, start, req.params.id, organizationId]);
  if (result.rowCount === 0) return res.status(404).json({ message: 'Schedule not found.' });
  res.json({ message: 'Schedule saved.' });
});

app.patch('/api/assessment-schedules/:id', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  if (typeof req.body.Enabled !== 'boolean') return res.status(422).json({ message: 'Enabled is required.' });
  const result = await pool.query(`UPDATE AssessmentSchedule SET Enabled = $1 WHERE ScheduleID = $2 AND OrganizationID = $3`,
    [req.body.Enabled, req.params.id, organizationId]);
  if (result.rowCount === 0) return res.status(404).json({ message: 'Schedule not found.' });
  res.json({ message: 'Schedule status updated.' });
});

app.delete('/api/assessment-schedules/:id', requireLogin, async (req, res) => {
  const organizationId = getOrganizationId(req);
  const result = await pool.query('DELETE FROM AssessmentSchedule WHERE ScheduleID = $1 AND OrganizationID = $2', [req.params.id, organizationId]);
  if (result.rowCount === 0) return res.status(404).json({ message: 'Schedule not found.' });
  res.status(204).send();
});

app.listen(3000, () => {
  console.log('Server running at http://localhost:3000');
});
