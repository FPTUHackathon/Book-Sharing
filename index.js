const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const passport = require('passport')
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt
const axios = require('axios')
const { Pool } = require('pg')
const config = require('./config')
const utils = require('./utils')

const app = express();
const PORT = process.env.PORT || 5000

// JWT settings
const jwtOptions = {}
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken()
jwtOptions.secretOrKey = 'booksharingg'

passport.use(new JwtStrategy(jwtOptions, (payload, done) => {
  pool.query('SELECT * FROM users WHERE userid = $1', [payload.userid])
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
  const page = parseInt(req.query.p, 10)
  let { sort } = req.query
  if (!sort || ['sale', 'comment'].indexOf(sort) < 0) {
    sort = 'sale'
  }
  const queryString =
    `SELECT books.*, COUNT(posts.id) as count, (SELECT COUNT(*) FROM comments WHERE comments.bookid = posts.bookid) as comment_count
    FROM books LEFT JOIN posts ON books.id = posts.bookid 
    GROUP BY books.id , comment_count
    ORDER BY ${sort === 'sale' ? 'count' : 'comment_count'} DESC
    ${page ? (`LIMIT ${config.itemsPerPage} OFFSET ${(page - 1) * config.itemsPerPage}`) : ''}`
  pool.query(queryString)
    .then((result) => {
      res.json(result.rows)
    })
})

app.get('/book/:id', (req, res) => {
  const { id } = req.params
  if (!id || isNaN(id)) {
    res.status(404).json('Book not found')
  }
  pool.query(
    'SELECT books.*, '
    + '(SELECT count(*) FROM posts WHERE'
    + 'array_agg(tags.name) as tags '
    + 'FROM books LEFT JOIN books_tags ON books.id = books_tags.bookid '
    + 'INNER JOIN tags ON books_tags.tagid = tags.id '
    + 'WHERE books.id = 1 '
    + 'GROUP BY books.id',
    [req.params.id]
  ).then((result) => {
    if (result.rows.length === 0) {
      res.status(404).json('Book not found')
    } else {
      const book = result.rows[0]
      if (book.tags) {
        book.tags = book.tags.filter(tag => tag !== null)
      }
      res.json(book)
    }
  }).catch(() => {
    res.status(404).json('Book not found')
  })
})

app.get('/isbn/:isbn', (req, res) => {
  pool.query(
    'SELECT books.*, COUNT(posts.id) as count, '
    + '(SELECT COUNT(*) FROM comments WHERE comments.bookid = posts.bookid) as comment_count '
    + 'FROM books LEFT JOIN posts ON books.id = posts.bookid '
    + 'WHERE isbn = $1 '
    + 'GROUP BY books.id , comment_count',
    [req.params.isbn]
  ).then((result) => {
    res.json(result.rows[0])
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
        let { username, email } = req.body
        const { password } = req.body
        username = username.trim()
        email = email.trim()
        bcrypt.hash(password, config.passwordHashRounds, (err, hash) => {
          pool.query(
            'INSERT INTO users (email, password, username) VALUES ($1, $2, $3)',
            [email, hash, username || email]
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
  axios.get(`https://graph.facebook.com/me?fields=id,name,email,location&access_token=${token}`)
    .then((response) => {
      const { data } = response
      data.avatar = `https://graph.facebook.com/${data.id}/picture?type=large`
      utils.providerLogin(pool, 'facebook', data)
      .then((result) => {
        const user = result.rows[0]
        const payload = { userid: result.rows[0].userid }
        const jwtToken = jwt.sign(payload, jwtOptions.secretOrKey, { expiresIn: '7 days' })
        res.json({
          success: true,
          token: jwtToken,
          user: {
            userid: user.userid,
            username: user.username,
            avatar: user.avatar,
            location: user.location,
            email: user.email,
            provider_id: user.provider_id,
            provider: user.provider
          }
        })
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
          const payload = { userid: user.userid }
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
    `SELECT userid, username, email, provider_id, provider, avatar, location
    FROM users WHERE ${isNaN(req.params.id) ? 'email = $1' : 'userid = $1'}`,
    [req.params.id]
  ).then((result) => {
      if (result.rows.length > 0) {
        res.json(result.rows[0])
      } else {
        res.status(404).json('User not found')
      }
    })
})

app.get('/posts/:bookid', passport.authenticate('jwt', { session: false }), (req, res) => {
  const { bookid } = req.params
  if (!bookid || isNaN(bookid)) {
    res.status(404).json('Book not found')
  } else {
    pool.query(
      'SELECT posts.*, users.*, books.*, array_agg(post_images.image) as images '
      + 'FROM posts INNER JOIN users ON posts.uid = users.userid '
      + 'INNER JOIN books ON posts.bookid = books.id '
      + 'LEFT JOIN post_images ON posts.id = post_images.pid '
      + 'WHERE posts.bookid = $1 '
      + 'GROUP BY posts.id, users.userid, books.id '
      + 'ORDER BY timestamp DESC',
      [bookid]
    ).then((result) => {
      res.json(result.rows.map(row => ({
        id: row.id,
        content: row.content,
        price: row.price,
        sold: row.sold,
        timestamp: row.timestamp,
        images: row.images.filter(img => img !== null),
        isOwner: req.user.userid === row.userid,
        user: {
          userid: row.userid,
          username: row.username,
          provider_id: row.provider_id,
          provider: row.provider,
          email: row.email,
          avatar: row.avatar,
          location: row.location
        },
        book: {
          id: row.bookid,
          name: row.name,
          cover: row.cover,
          isbn: row.isbn,
          author: row.author,
          description: row.description,
        }
      })))
    }).catch(() => {
      res.status(500).json('Server error')
    })
  }
})

app.post('/posts', passport.authenticate('jwt', { session: false }), (req, res) => {
  const { bookid, content, price, status, images } = req.body
  if (!bookid || isNaN(bookid)) {
    res.status(404).json('Book not found')
  } else {
    pool.query('SELECT * FROM books WHERE id = $1', [bookid])
      .then((result) => {
        if (result.rows.length === 1) {
          return pool.query(
            'INSERT INTO posts (bookid, uid, content, status, price) '
            + 'VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [bookid, req.user.userid, content, parseInt(status, 10) || 0, parseInt(price, 10) || null]
          ).then((rec) => {
            const uploaded = []
            if (images instanceof Array) {
              for (let i = 0; i < images.length; i++) {
                uploaded.push(images[i])
              }
            } else if (images) {
              uploaded.push(images)
            }
            if (uploaded.length > 0) {
              return pool.query(
                `INSERT INTO post_images (pid, image) VALUES
                ('${uploaded.map(img => `${rec.rows[0].id}','${img}`).join('\'), (\'')}')`
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

app.get('/comments/:bookid', (req, res) => {
  const { bookid } = req.params
  const page = parseInt(req.query.p, 10) || 1

  if (!bookid || isNaN(bookid)) {
    res.status(404).json('Book not found')
  } else {
    pool.query(
      `SELECT comments.*, users.username, users.avatar, users.location, users.email FROM comments
      INNER JOIN users ON comments.uid = users.userid
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
      [bookid, req.user.userid, content.trim()]
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
    'SELECT books.*, COUNT(posts.id) as count ' 
    + 'FROM favorites INNER JOIN books ON favorites.bookid = books.id '
    + 'LEFT JOIN posts ON books.id = posts.bookid '
    + 'WHERE favorites.uid = $1 GROUP BY books.id',
    [req.user.userid]
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
          [req.user.userid, bookid]
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
    [req.user.userid, bookid]
  ).then(() => {
    res.json({ success: true })
  }).catch(() => {
    res.status(500).json('Server error')
  })
})

app.get('/tags', (req, res) => {
  pool.query('SELECT * FROM tags ORDER BY name')
    .then((result) => {
      res.json(result.rows)
    }).catch(() => {
      res.status(500).json('Server error')
    })
})

app.get('/tags/:bookid', (req, res) => {
  const { bookid } = req.params
  if (!bookid || isNaN(bookid)) {
    res.status(404).json('Invalid parameter(s)')
    return
  }
  pool.query(
    'SELECT tags.name '
    + 'FROM books_tags INNER JOIN tags ON books_tags.tagid = tags.id '
    + 'WHERE books_tags.bookid = $1 '
    + 'ORDER BY tags.name',
    [bookid]
  ).then((result) => {
    res.json(result.rows.map(row => row.name))
  }).catch(() => {
    res.status(500).json('Server error')
  })
})

app.get('/tag/:id', (req, res) => {
  const { id } = req.params
  if (!id || isNaN(id)) {
    res.status(404).json('Invalid parameter(s)')
    return
  }
  pool.query(
    'SELECT books.*, tags.name as tag, COUNT(posts.id) as count '
    + 'FROM books_tags INNER JOIN books ON books_tags.bookid = books.id '
    + 'INNER JOIN tags ON books_tags.tagid = tags.id '
    + 'LEFT JOIN posts ON books.id = posts.bookid '
    + 'WHERE books_tags.tagid = $1 GROUP BY books.id',
    [id]
  ).then((result) => {
    res.json({
      tag: result.rows.length ? result.rows[0].tag : null,
      books: result.rows.map(
        row => ({ id: row.id, name: row.name, cover: row.cover, isbn: row.isbn })
      )
    })
  }).catch(() => {
    res.status(500).json('Server error')
  })
})

app.get('/tag-name', (req, res) => {
  const { tag } = req.query
  if (!tag) {
    res.status(404).json('Invalid parameter(s)')
    return
  }
  pool.query(
    'SELECT books.*, COUNT(posts.id) as count '
    + 'FROM books_tags INNER JOIN books ON books_tags.bookid = books.id '
    + 'INNER JOIN tags ON books_tags.tagid = tags.id '
    + 'LEFT JOIN posts ON books.id = posts.bookid '
    + 'WHERE tags.name = $1 GROUP BY books.id',
    [tag]
  ).then((result) => {
    res.json({
      tag,
      books: result.rows
    })
  }).catch(() => {
    res.status(500).json('Server error')
  })
})

app.get('/profile/posts', passport.authenticate('jwt', { session: false }), (req, res) => {
  pool.query(
    'SELECT posts.*, books.name, books.cover, books.isbn, books.author, books.description, array_agg(post_images.image) as images '
    + 'FROM posts INNER JOIN books ON posts.bookid = books.id '
    + 'LEFT JOIN post_images ON posts.id = post_images.pid '
    + 'WHERE uid = $1 '
    + 'GROUP BY posts.id, books.name, books.cover, books.isbn, books.author, books.description '
    + 'ORDER BY posts.id',
    [req.user.userid]
  ).then((result) => {
    res.json(result.rows.map(row => ({
      id: row.id,
      content: row.content,
      price: row.price,
      sold: row.sold,
      timestamp: row.timestamp,
      images: row.images.filter(img => img !== null),
      book: {
        id: row.bookid,
        name: row.name,
        cover: row.cover,
        isbn: row.isbn,
        author: row.author,
        description: row.description,
      }
    })))
  }).catch(() => {
    res.status(500).json('Server error')
  })
})

app.get('/search', (req, res) => {
  const { q } = req.query
  if (!q) {
    res.json([])
  } else {
    const words = q.split(/\s+/)
    pool.query(
      'SELECT books.*, COUNT(posts.id) as count '
      + 'FROM books LEFT JOIN posts ON books.id = posts.bookid '
      + 'WHERE to_tsvector(unaccent(removemarks(name))) @@ to_tsquery(unaccent(removemarks($1)))'
      + 'GROUP BY books.id',
      [words.join(' & ')]
    ).then((result) => {
      res.json(result.rows)
    }).catch(() => {
      res.status(500).json('Server error')
    })
  }
})

app.delete('/post/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
  const { id } = req.params
  if (!id || isNaN(id)) {
    res.status(404).json('Post not found')
  }
  pool.query(
    'DELETE FROM posts WHERE id = $1 AND uid = $2 RETURNING *', [id, req.user.userid]
  ).then((result) => {
    if (result.rows.length === 0) {
      res.status(404).json('Post not found')
    } else {
      const post = result.rows[0]
      res.json(post)
    }
  }).catch(() => {
    res.status(500).json('Server error')
  })
})

app.listen(PORT, () => console.log(`Listening on ${PORT}`))
