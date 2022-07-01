require('dotenv').config();
const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const cors = require('cors');
const database = require('./database');
const crypto = require('crypto');

app.use(cors());
app.use(express.json());

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401); // if there isn't any token
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

app.get('/rooms', async (req, res) => {
    authenticateToken(req, res , () => {});
    const userid = req.user.user.user.id;
    const connection = await database.getConnection();
    const userrooms = await connection.query('SELECT * FROM userroom WHERE user_id = ?', [userid]);

    if (userrooms == null || userrooms.length === 0) {
        connection.end();
        return res.status(200).json([])
    };

    var all_rooms = await connection.query('SELECT * FROM room');

    if (all_rooms == null || all_rooms.length === 0) {
        connection.end();
        return res.status(200).json([]);
    };

    var rooms = [];
    for (var i = 0; i < userrooms.length; i++) {
        var room = all_rooms.find(r => r.id == userrooms[i].room_id);
        if (room) rooms.push(room);
    }

    connection.end();

    return res.json(rooms);
});

app.post('/room', async (req, res) => {
    authenticateToken(req, res , () => {});

    console.log(req.user)

    const userid = req.user.user.user.id;
    const roomid = crypto.randomUUID();
    const roomname = req.body.roomname;
    const connection = await database.getConnection();

    connection.query(
        'INSERT INTO room (id, name, created_at) VALUES (?, ?, NOW())',
        [roomid, roomname],
        (err, rows) => {
            if (err) {
                connection.end();
                return res.status(500).json({
                    error: 'Something went wrong'
                });
            }
        }
    );
    connection.query(
        'INSERT INTO userroom (user_id, room_id, joined_at) VALUES (?, ?, NOW())',
        [userid, roomid],
        (err, rows) => {
            if (err) {
                connection.end();
                return res.status(500).json({
                    error: 'Something went wrong'
                });
            }
        }
    );
    connection.end();
    return res.status(200).json({
        message: 'Room created'
    });
});

app.listen(3002, () => {
    console.log('Server started on port 3002');
});