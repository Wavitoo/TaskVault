const jwt = require('jsonwebtoken');
const pool = require('../db/pool');

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // format attendu: "Bearer <token>"

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, async (err, payload) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    // Un jeton sans identifiant (jti) ne peut pas être révoqué : on le refuse.
    if (!payload.jti) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    try {
      const revoked = await pool.query('SELECT 1 FROM revoked_tokens WHERE jti = $1', [payload.jti]);
      if (revoked.rows.length > 0) {
        return res.status(401).json({ error: 'Token revoked' });
      }
    } catch (dbErr) {
      console.error(dbErr);
      return res.status(500).json({ error: 'Internal server error' });
    }

    req.user = payload; // contient userId, username, jti, exp -> disponible dans les routes suivantes
    next();
  });
}

module.exports = authenticateToken;
