const express = require('express');
const path = require('path');
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
    res.redirect('/overview');
  } else {
    res.status(401).send('Wrong username or password.');
  }
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'SWE Project.html'));
});

app.get('/overview', (req, res) => {
  res.sendFile(path.join(__dirname, 'overview.html'));
});
app.get('/inventory', (req, res) => {
  res.sendFile(path.join(__dirname, 'inventory.html'));
});

app.get('/api/dashboard', async (req, res) => {
  try {
    const assets = await pool.query(
      'SELECT COUNT(*)::int AS count FROM InventoryAsset WHERE OrganizationID = 1'
    );
    const findings = await pool.query(
      "SELECT COUNT(*)::int AS count FROM Finding WHERE OrganizationID = 1 AND FindingStatus = 'Open'"
    );
    const priority = await pool.query(`
      SELECT v.CVE AS cve,
             a.AssetName AS asset,
             v.CVSSScore AS cvss,
             v.Severity AS severity,
             f.FindingStatus AS status,
             TO_CHAR(f.FirstDetected, 'YYYY-MM-DD') AS discovered
      FROM Finding f
      JOIN Vulnerability v ON v.VulnerabilityID = f.VulnerabilityID
      JOIN InventoryAsset a ON a.AssetID = f.AssetID
      WHERE f.OrganizationID = 1
      ORDER BY v.CVSSScore DESC NULLS LAST
      LIMIT 5
    `);

    res.json({
      assets: assets.rows[0].count,
      findings: findings.rows[0].count,
      priorityFindings: priority.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load dashboard data' });
  }
});

app.get('/api/assets', async (req, res) => {
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
      WHERE a.OrganizationID = 1
        AND ($1 = '' OR a.AssetName ILIKE '%' || $1 || '%' OR a.Product ILIKE '%' || $1 || '%')
        AND ($2 = '' OR t.AssetTypeName = $2)
        AND ($3 = '' OR a.Vendor ILIKE $3)
      GROUP BY a.AssetID, t.AssetTypeName
      ORDER BY a.AssetName
    `, [q, typeNames[type] || '', vendor]);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load assets' });
  }
});

app.post('/api/assets', async (req, res) => {
  const { type, status, name, vendor, product, software, public: isPublic } = req.body;

  if (!name || !type) {
    return res.status(400).json({ error: 'Asset name and type are required' });
  }

  try {
    const result = await pool.query(`
      INSERT INTO InventoryAsset
        (OrganizationID, AssetTypeID, AssetName, Vendor, Product, Version, PublicFacing, Status)
      SELECT 1, AssetTypeID, $2, $3, $4, $5, $6, $7
      FROM AssetType
      WHERE AssetTypeName = $1
      RETURNING AssetID AS id
    `, [type, name, vendor, product, software, isPublic === 'Yes', status === 'pause' ? 'Paused' : 'Active']);

    if (result.rowCount === 0) {
      return res.status(400).json({ error: 'Unknown asset type' });
    }

    res.status(201).json({ id: result.rows[0].id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not save asset' });
  }
});

app.post('/api/assets/import', async (req, res) => {
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
        SELECT 1, AssetTypeID, $2, $3, $4, $5, $6, 'Active'
        FROM AssetType
        WHERE LOWER(AssetTypeName) = LOWER($1)
      `, [r.type, r.name, r.vendor || null, r.product || null, r.version || null,
          ['yes', 'true'].includes(String(r.public).toLowerCase())]);

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

app.listen(3000, () => {
  console.log('Server running at http://localhost:3000');
});