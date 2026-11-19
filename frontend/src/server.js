const express = require('express');
const app = express();

app.get(`/api/assets`, async (req, res) => {
    const{ rows } = await pool.query('SELECT * FROM InventoryAsset');
    res.json(rows);
}) 