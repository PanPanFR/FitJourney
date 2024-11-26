const Hapi = require('@hapi/hapi');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const User = require('./models/User'); // Import model User

const JWT_SECRET = 'secretkey123';

const init = async () => {
    // Koneksi ke MongoDB
    await mongoose.connect('mongodb://127.0.0.1:27017/backend_login', {
    });
    console.log('Connected to MongoDB');

    const server = Hapi.server({
        port: 3000,
        host: 'localhost',
    });

    // Route untuk register
    server.route({
        method: 'POST',
        path: '/register',
        handler: async (request, h) => {
            const { username, password } = request.payload;

            try {
                // Cek apakah username sudah digunakan
                const existingUser = await User.findOne({ username });
                if (existingUser) {
                    return h.response({ message: 'Username already exists' }).code(400);
                }

                // Hash password dan simpan ke database
                const hashedPassword = await bcrypt.hash(password, 10);
                const newUser = new User({ username, password: hashedPassword });
                await newUser.save();

                return h.response({ message: 'User registered successfully' }).code(201);
            } catch (error) {
                console.error(error);
                return h.response({ message: 'Internal Server Error' }).code(500);
            }
        },
    });

    // Route untuk login
    server.route({
        method: 'POST',
        path: '/login',
        handler: async (request, h) => {
            const { username, password } = request.payload;

            try {
                // Cek apakah username ada di database
                const user = await User.findOne({ username });
                if (!user) {
                    return h.response({ message: 'Invalid username or password' }).code(401);
                }

                // Verifikasi password
                const isValid = await bcrypt.compare(password, user.password);
                if (!isValid) {
                    return h.response({ message: 'Invalid username or password' }).code(401);
                }

                // Buat token JWT
                const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });

                return h.response({ message: 'Login successful', token }).code(200);
            } catch (error) {
                console.error(error);
                return h.response({ message: 'Internal Server Error' }).code(500);
            }
        },
    });

    await server.start();
    console.log('Server running on %s', server.info.uri);
};

process.on('unhandledRejection', (err) => {
    console.log(err);
    process.exit(1);
});

init();
