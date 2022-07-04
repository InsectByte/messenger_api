require('dotenv').config();
const jwt = require('jsonwebtoken');
const mariadb = require('mariadb');
const express = require('express');
const app = express();
const http = require('http');
const { SocketAddress } = require('net');
const server = http.createServer(app);
const { Server } = require("socket.io");
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: 'GET, POST, PUT, DELETE, OPTIONS',
    allowedHeaders: 'Content-Type, Authorization, Content-Length, X-Requested-With',
  },
});
const socketioJwt   = require('socketio-jwt');

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

io.use(socketioJwt.authorize({
    secret: process.env.JWT_SECRET,
    handshake: true,
}));
 
io.on('connect', (socket) => {
  console.log(socket.decoded_token.user.user.username + ' has connected');

    socket.on('disconnect', () => {
        console.log(socket.decoded_token.user.user.username + ' has disconnected');
        socket.removeAllListeners();
    });

    socket.on('join', roomId => {
        let room = roomId;
        
        Array.from(socket.rooms)
            .filter(room => room !== socket.id)
            .forEach(id => {
                socket.leave(id);
                console.log(socket.decoded_token.user.user.username + ' has left room ' + id);
                socket.removeAllListeners(`onMessage`)
            });
            console.log(`${socket.decoded_token.user.user.username} joined ${room}`);
        socket.join(room);

        socket.on('onMessage', message => {
            var message_obj = {
                message: message,
                user: socket.decoded_token.user.user.username,
                created_at: new Date(),
            };
            console.log(message_obj);
            Array.from(socket.rooms)
                .filter(room => room !== socket.id)
                .forEach(id => {
                    console.log(`${socket.decoded_token.user.user.username} sent ${message_obj.message} to ${id}`);
                    socket.to(id).emit('onMessage', message_obj);
                });
        });
    });
});
 
server.listen(3000, () => {
  console.log('listening on *:3000');
});