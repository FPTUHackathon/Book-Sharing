const utils = {}

utils.providerLogin = (pool, provider, data) =>
  pool.query(
    'SELECT * FROM users WHERE provider = $1 AND provider_id = $2',
    [provider, data.id]
  ).then((result) => {
    if (result.rows.length > 0) {
      return pool.query(
        'UPDATE users SET name = $1 WHERE provider = $2 AND provider_id = $3 RETURNING *',
        [data.name, provider, data.id]
      )
    }
    return pool.query(
      'INSERT INTO users (name, provider_id, provider) VALUES ($1, $2, $3) RETURNING *',
      [data.name, data.id, provider]
    )
  })

module.exports = utils
