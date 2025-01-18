const jwt = require('jsonwebtoken');
const secretKey = process.env.JWT_SECRET;

// Function to generate token
async function generateToken(user) {
    try {
        const token = jwt.sign({ user_id: user.user_id, role: user.role }, secretKey, { expiresIn: '1h' });
        return token;
    } catch (error) {
        console.error("Error generating token:", error);
        throw new Error("Error generating token");
    }
}

// Middleware to check admin role
const ADMIN = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).send('Authorization header missing');
        }

        if (!authHeader.startsWith('Bearer ')) {
            return res.status(401).send('Authorization header is not in Bearer format');
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        
        if (decoded.role === 'admin') {
            req.user = decoded;
            return next();
        } else {
            return res.status(403).send('Access denied');
        }
    } catch (error) {
        console.error("Error in ADMIN middleware:", error);
        return res.status(401).send('Invalid token or unauthorized');
    }
};

// Middleware to check user authentication
const USER = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).send('Authorization header missing');
        }

        if (!authHeader.startsWith('Bearer ')) {
            return res.status(401).send('Authorization header is not in Bearer format');
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        
        req.user = decoded;
        return next();
    } catch (error) {
        console.error("Error in USER middleware:", error);
        return res.status(401).send('Invalid token or unauthorized');
    }
};

module.exports = {
    generateToken,
    ADMIN,
    USER
};
