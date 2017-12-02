const utils = {}

utils.providerLogin = (pool, provider, data) =>
  pool.query(
    'SELECT * FROM users WHERE provider = $1 AND provider_id = $2',
    [provider, data.id]
  ).then((result) => {
    if (result.rows.length > 0) {
      return pool.query(
        'UPDATE users SET name = $1, avatar = $2, location = $3, email = $4 WHERE provider = $5 AND provider_id = $6 RETURNING *',
        [data.name, data.avatar, data.location ? data.location.name : null, data.email || null, provider, data.id]
      )
    }
    return pool.query(
      'INSERT INTO users (name, avatar, location, provider_id, provider) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [data.name, data.avatar, data.location ? data.location.name : null, data.email || null, data.id, provider]
    )
  })

module.exports = utils
