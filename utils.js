const utils = {}

utils.providerLogin = (pool, provider, data) =>
  pool.query(
    'SELECT * FROM users WHERE provider = $1 AND provider_id = $2',
    [provider, data.id]
  ).then((result) => {
    if (result.rows.length > 0) {
      return pool.query(
        'UPDATE users SET name = $1, avatar = $2 WHERE provider = $3 AND provider_id = $4 RETURNING *',
        [data.name, data.avatar, provider, data.id]
      )
    }
    return pool.query(
      'INSERT INTO users (name, avatar, provider_id, provider) VALUES ($1, $2, $3, $4) RETURNING *',
      [data.name, data.avatar, data.id, provider]
    )
  })

module.exports = utils
