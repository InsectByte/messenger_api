require('dotenv').config();
const express = require('express');
const app = express();

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const cors = require('cors');
app.use(cors());

let refreshTokens = [];

const database = require('./database');

app.use(express.json());

function generateAccessToken(user) {
    return jwt.sign({ user }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRATION,
    });
}

async function encryptPassword(password) {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
}

async function getUser(username) {
    const connection = await database.getConnection();
    const [rows] = await connection.query(
        'SELECT * FROM users WHERE username = ?',
        [username]
    );
    connection.end();
    if (rows == null || rows.length === 0) {
        return null;
    }
    return rows;
}

app.post('/login', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    const user = await getUser(username);
    if (!user) {
        return res.status(400).json({
            error: 'Username and password do not match',
        });
    }

    bcrypt.compare(password, user.password, (err, result) => {
        if (err) {
            return res.status(500).json({
                error: 'Something went wrong',
            });
        }
        if (!result) {
            return res.status(400).json({
                error: 'Username and password do not match',
            });
        }
        const accessToken = generateAccessToken({
            user: {
                id: user.id,
                username: user.username,
            }
        });
        const refreshToken = jwt.sign( {
            user: {
                id: user.id,
                username: user.username,
            }
        } , process.env.REFRESH_SECRET);
        refreshTokens.push(refreshToken);
        res.json({
            accessToken,
            refreshToken,
        });
    });

});

app.post('/signup', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const id = crypto.randomUUID();

    console.log(username, password, id);

    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    const encryptedPassword = await encryptPassword(password);

    let conn;
    try {
        conn = await database.getConnection();

        const query = await conn.query("INSERT INTO users (id, username, password, created_at) values (?, ?, ?, NOW())", [id, username, encryptedPassword]);
        console.log(query);
        res.send('User created').status(200).send(); // { affectedRows: 1, insertId: 1, warningStatus: 0 }
    } catch (err) {
        res.status(500).send('Something went wrong while creating your account!');
        throw err;
    } finally {
        if (conn) return conn.end();
    }

    
});

app.delete('/logout', (req, res) => {
    const refreshToken = req.body.refreshToken;
    refreshTokens = refreshTokens.filter(token => token !== refreshToken);
    res.sendStatus(204);
});

app.post('/refresh', (req, res) => {
    const refreshToken = req.body.refreshToken;
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
    jwt.verify(refreshToken, process.env.REFRESH_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        const accessToken = generateAccessToken(user.id);
        res.json({ accessToken: accessToken }).status(200).send();
    }
    );
});

app.listen(3001, () => {
    console.log('listening on *:3001');
});

