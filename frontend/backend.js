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

app.listen(3000, () => {
  console.log('Server running at http://localhost:3000');
});