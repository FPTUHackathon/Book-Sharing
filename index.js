const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const passport = require('passport')
const crypto = require('crypto')
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt
const multer = require('multer')
const mime = require('mime')
const axios = require('axios')
const { Pool } = require('pg')
const config = require('./config')
const utils = require('./utils')

const app = express();
const PORT = process.env.PORT || 5000
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads/')
  },
  filename: (req, file, cb) => {
    crypto.pseudoRandomBytes(16, (err, raw) => {
      cb(null, `${raw.toString('hex')}${Date.now()}.${mime.getExtension(file.mimetype)}`);
    });
  }
});
const upload = multer({ storage });

// JWT settings
const jwtOptions = {}
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken()
jwtOptions.secretOrKey = 'booksharingg'

passport.use(new JwtStrategy(jwtOptions, (payload, done) => {
  pool.query('SELECT * FROM users WHERE id = $1', [payload.id])
    .then((result) => {
      if (result.rows.length === 1) {
        return done(null, result.rows[0])
      }
      return done(null, false)
    }).catch((err) => done(err, false))
}));

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

// the pool with emit an error on behalf of any idle clients
// it contains if a backend error or network partition happens
pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err)
  process.exit(-1)
})

app.use(bodyParser.json())
  .use(bodyParser.urlencoded({ extended: true }))
  .use(express.static(path.join(__dirname, 'public')))

app.get('/books', (req, res) => {
  const page = parseInt(req.query.p, 10) || 1
  const queryString =
    `SELECT books.*, COUNT(posts.id) as count 
    FROM books LEFT JOIN posts ON books.id = posts.bookid 
    GROUP BY books.id 
    ORDER BY count DESC
    LIMIT ${config.itemsPerPage} OFFSET ${(page - 1) * config.itemsPerPage}`
  pool.query(queryString)
    .then((result) => {
      res.json(result.rows)
    })
})

app.get('/book/:id', (req, res) => {
  pool.query('SELECT * FROM books WHERE id = $1', [req.params.id])
    .then((result) => {
      if (result.rows.length === 0) {
        res.status(404).json('Book not found')
      }
      res.json(result.rows[0])
    }).catch(() => {
      res.status(404).json('Book not found')
    })
})

app.get('/isbn/:isbn', (req, res) => {
  pool.query(
    'SELECT * FROM books WHERE isbn = $1',
    [req.params.isbn]
  ).then((result) => {
    res.json(result.rows)
  }).catch(() => {
    res.status(500).json('Server error')
  })
})

app.post('/register', (req, res) => {
  pool.query('SELECT * FROM users WHERE email = $1', [req.body.email.trim()])
    .then((result) => {
      if (result.rows.length > 0) {
        res.status(400).json('Email already exists')
      } else {
        let { name, email } = req.body
        const { password } = req.body
        name = name.trim()
        email = email.trim()
        bcrypt.hash(password, config.passwordHashRounds, (err, hash) => {
          pool.query(
            'INSERT INTO users (email, password, name) VALUES ($1, $2, $3)',
            [email, hash, name || email]
          ).then(() => {
            res.json({
              success: true
            })
          })
        })
      }
    })
    .catch(() => {
      res.status(500).json('Server error')
    })
})

app.post('/auth/facebook', (req, res) => {
  const { token } = req.body
  axios.get(`https://graph.facebook.com/me?fields=id,name&access_token=${token}`)
    .then((response) => {
      const { data } = response
      utils.providerLogin(pool, 'facebook', data)
      .then((result) => {
        const payload = { id: result.rows[0].id }
        const jwtToken = jwt.sign(payload, jwtOptions.secretOrKey)
        res.json({ success: true, token: jwtToken, user: result.rows[0] })
      })
      .catch(() => {
        res.status(500).json('Server error')
      })
    }).catch(() => {
      res.status(401).json('Invalid token')
    })
})

app.post('/login', (req, res) => {
  const { email, password } = req.body
  if (!email || !password) {
    res.status(401).json('Wrong email/password')
  }
  pool.query(
    'SELECT * FROM users WHERE email = $1',
    [email.trim()]
  ).then((result) => {
    if (result.rows.length === 1) {
      const user = result.rows[0]
      bcrypt.compare(password, user.password, (error, success) => {
        if (success) {
          const payload = { id: user.id }
          const token = jwt.sign(payload, jwtOptions.secretOrKey)
          res.json({ success: true, token })
        } else {
          res.status(401).json('Wrong password')    
        }
      })
    } else {
      res.status(401).json('Wrong email')
    }
  }).catch(() => {
    res.status(500).json('Server error')
  })
})

app.get('/user/:id', (req, res) => {
  pool.query(
    `SELECT id, name, email, provider_id, provider
    FROM users WHERE ${isNaN(req.params.id) ? 'email = $1' : 'id = $1'}`,
    [req.params.id]
  ).then((result) => {
      if (result.rows.length > 0) {
        res.json(result.rows[0])
      } else {
        res.status(404).json('User not found')
      }
    })
})

app.get('/posts/:bookid', (req, res) => {
  const { bookid } = req.params
  if (!bookid || isNaN(bookid)) {
    res.status(404).json('Book not found')
  } else {
    pool.query(
      'SELECT posts.*, users.id as userId, users.name as userName '
      + 'FROM posts INNER JOIN users ON posts.uid = users.id '
      + 'WHERE posts.bookid = $1',
      [bookid]
    ).then((result) => {
      res.json(result.rows)
    }).catch(() => {
      res.status(500).json('Server error')
    })
  }
})

app.post('/posts', passport.authenticate('jwt', { session: false }), upload.array('photos', 10), (req, res) => {
  const { bookid, content, price, status } = req.body
  if (!bookid || isNaN(bookid)) {
    res.status(404).json('Book not found')
  } else {
    pool.query('SELECT * FROM books WHERE id = $1', [bookid])
      .then((result) => {
        if (result.rows.length === 1) {
          return pool.query(
            'INSERT INTO posts (bookid, uid, content, status, price) '
            + 'VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [bookid, req.user.id, content, status, parseInt(price, 10) || null]
          ).then((rec) => {
            if (req.files && req.files.length > 0) {
              return pool.query(
                `INSERT INTO post_images (pid, image) VALUES
                ('${req.files.map(f => `${rec.rows[0].id}','${f.filename}`).join('\'), (\'')}')`
              )
            }
            return Promise.resolve()
          }).then(() => {
            res.json({
              success: true
            })
          })
        }
        res.status(404).json('Book not found')
      }).catch(() => {
        res.status(500).json('Server error')
      })
  }
})

app.get('/post/:id', (req, res) => {
  const { id } = req.params
  if (!id || isNaN(id)) {
    res.status(404).json('Post not found')
  } else {
    pool.query('SELECT * FROM posts WHERE id = $1', [id]).then((result) => {
      if (result.rows.length === 1) {
        res.json(result.rows[0])
      } else {
        res.status(404).json('Post not found')
      }
    })
  }
})

app.get('/comments/:bookid', (req, res) => {
  const { bookid } = req.params
  const page = parseInt(req.query.p, 10) || 1

  if (!bookid || isNaN(bookid)) {
    res.status(404).json('Book not found')
  } else {
    pool.query(
      `SELECT * FROM comments
      WHERE bookid = $1
      ORDER BY timestamp DESC
      LIMIT ${config.itemsPerPage} OFFSET ${(page - 1) * config.itemsPerPage}`,
      [bookid]
    ).then((result) => {
      res.json(result.rows)
    }).catch(() => {
      res.status(500).json('Server error')
    })
  }
})

app.post('/comments', passport.authenticate('jwt', { session: false }), (req, res) => {
  const { bookid, content } = req.body
  if (!bookid || !content || isNaN(bookid)) {
    res.status(404).json('Book not found')
  } else {
    pool.query(
      'INSERT INTO comments (bookid, uid, content) VALUES ($1, $2, $3) RETURNING *',
      [bookid, req.user.id, content.trim()]
    ).then((result) => {
      res.json({
        success: true,
        comment: result.rows[0]
      })
    }).catch(() => {
      res.status(500).json('Server error')
    })
  }
})

app.get('/comment/:id', (req, res) => {
  const { id } = req.params
  if (!id || isNaN(id)) {
    res.status(404).json('Comment not found')
  } else {
    pool.query('SELECT * FROM comments WHERE id = $1', [id])
      .then((result) => {
        if (result.rows.length === 1) {
          res.json(result.rows[0])
        } else {
          res.status(404).json('Comment not found')
        }
      }).catch(() => {
        res.status(500).json('Server error')
      })
  }
})

app.get('/favorites', passport.authenticate('jwt', { session: false }), (req, res) => {
  pool.query(
    'SELECT books.* FROM favorites INNER JOIN books ON favorites.bookid = books.id WHERE uid = $1',
    [req.user.id]
  ).then((result) => {
    res.json(result.rows)
  }).catch(() => {
    res.status(500).json('Server error')
  })
})

app.post('/favorites', passport.authenticate('jwt', { session: false }), (req, res) => {
  const { bookid } = req.body
  if (!bookid || isNaN(bookid)) {
    res.status(404).json('Book not found')
    return
  }
  pool.query('SELECT * FROM books WHERE id = $1', [bookid])
    .then((result) => {
      if (result.rows.length === 0) {
        res.status(404).json('Book not found')
      } else {
        pool.query(
          'INSERT INTO favorites (uid, bookid) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [req.user.id, bookid]
        ).then(() => {
          res.json({ success: true })
        })
      }
    }).catch(() => {
      res.status(500).json('Server error')
    })
})

app.delete('/favorites/:bookid', passport.authenticate('jwt', { session: false }), (req, res) => {
  const { bookid } = req.params
  if (!bookid || isNaN(bookid)) {
    res.status(404).json('Invalid parameter(s)')
    return
  }
  pool.query(
    'DELETE FROM favorites WHERE uid = $1 AND bookid = $2',
    [req.user.id, bookid]
  ).then(() => {
    res.json({ success: true })
  }).catch(() => {
    res.status(500).json('Server error')
  })
})

app.listen(PORT, () => console.log(`Listening on ${PORT}`))
