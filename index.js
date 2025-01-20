const express = require('express');
const { MongoClient, ServerApiVersion } = require('mongodb');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
dotenv.config();

const {
    createUser,
    createItem,
    createMonster,
    createTransaction,
    createWeapon
} = require('./Functions/CreateFunction');


const {
    findUserByUsername,
    findUserById
} = require('./Functions/FindFunction');

const {
    monsterslain,
    deleteUser,
    reportUser
} = require('./Functions/OtherFunction');

const { viewLeaderboard, viewUserByAdmin } = require('./Functions/ViewFunction');

const app = express();
const port = process.env.port || process.env.norman_port;

const credentials = process.env.credentials;

// Correct MongoDB connection initialization
const client = new MongoClient(process.env.MONGODB_URI, {
    tlsCertificateKeyFile: credentials,
    serverApi: ServerApiVersion.v1
});

// Establish and reuse MongoDB connection
let db;
async function connectToDatabase() {
    try {
        if (!db) {
            await client.connect();
            db = client.db("Cluster"); // Ensure a single connection to the database
            console.log("Connected to MongoDB");
        }
    } catch (error) {
        console.error("Failed to connect to MongoDB:", error);
        throw error;
    }
}

// Middleware
app.use(express.json());

const validatePassword = (password) => {
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$/;

    if (passwordRegex.test(password)) {
        return { valid: true, message: "Password is secure." };
    } else {
        return {
            valid: false,
            message: "Password must have at least 8 characters, including 1 uppercase letter, 1 number, and 1 special character."
        };
    }
};



// Example: Simplified Routes Using Shared DB Connection
app.post('/createUser', async (req, res) => {
    try {
        const { user_id, username, password, email, role = "user" } = req.body; // Default role is "user"
        const database = client.db('Cluster');
        const collection = database.collection('users');

        // Basic validation
        if (!user_id || !username || !password || !email) {
            return res.status(400).send("Missing required fields: user_id, username, password, or email");
        }

        // Validate email using Mailboxlayer API
        const validateEmail = async (email) => {
            try {
                const response = await axios.get(
                    `http://apilayer.net/api/check?access_key=${process.env.MAILBOXLAYER_API_KEY}&email=${encodeURIComponent(email)}`
                );
                return response.data;
            } catch (error) {
                console.error("Error validating email with Mailboxlayer:", error.message);
                throw new Error("Failed to validate email address.");
            }
        };

        let emailValidation;
        try {
            emailValidation = await validateEmail(email);
        } catch (error) {
            return res.status(500).send("Failed to validate email address.");
        }

        if (!emailValidation.format_valid || !emailValidation.smtp_check) {
            return res.status(400).send("Invalid email address. Please provide a valid and reachable email.");
        }

        // Validate password strength
        const passwordValidation = validatePassword(password);
        if (!passwordValidation.valid) {
            return res.status(400).send(passwordValidation.message);
        }

        // Check for duplicate user_id, username, or email
        const existingUser = await collection.findOne({
            $or: [{ user_id }, { username }, { email }]
        });

        if (existingUser) {
            if (existingUser.email === email) {
                return res.status(409).send("An account with this email already exists.");
            }
            return res.status(409).send("User with the same user_id or username already exists.");
        }

        // Hash the password for security
        const bcrypt = require('bcryptjs');
        const hashedPassword = await bcrypt.hash(password, 10);

        const user = {
            user_id,
            username,
            password: hashedPassword, // Store hashed password
            email,
            role, // Save the role in the user document
            registration_date: new Date().toISOString(),
            profile: {
                level: 1,
                experience: 0,
                attributes: {
                    strength: 0,
                    dexterity: 0,
                    intelligence: 0
                }
            },
            inventory: []
        };

        // Insert the user into the database
        await collection.insertOne(user);
        res.status(201).send("User created successfully");
    } catch (error) {
        console.error("Error in createUser route:", error);
        res.status(500).send("Error creating user");
    }
});


// Ensure server starts only after DB connection
connectToDatabase()
    .then(() => {
        app.listen(port, () => {
            console.log(`Server running on http://localhost:${port}`);
        });
    })
    .catch(err => {
        console.error("Error starting server:", err);
        process.exit(1);
    });

// Handle SIGINT for clean shutdown
process.on('SIGINT', async () => {
    console.log('Closing database connection...');
    await client.close();
    process.exit(0);
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).send("Missing required fields: username or password");
        }

        const database = client.db('Cluster');
        const collection = database.collection('users');

        // Find user by username
        const user = await collection.findOne({ username });

        if (!user) {
            return res.status(404).send("User not found");
        }

        // Check if the account is locked
        const currentTime = new Date();
        if (user.lockUntil && currentTime < user.lockUntil) {
            return res.status(403).send("Account is locked. Try again later.");
        }

        // Verify the password
        const bcrypt = require('bcryptjs');
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            // Increment failed attempts
            const failedAttempts = (user.failedAttempts || 0) + 1;

            if (failedAttempts >= 3) {
                // Lock the account for 1 minute
                await collection.updateOne(
                    { username },
                    { $set: { lockUntil: new Date(currentTime.getTime() + 1 * 60 * 1000), failedAttempts: 0 } }
                );
                return res.status(403).send("Account is locked due to multiple failed login attempts. Try again in 1 minute.");
            }

            // Update failed attempts
            await collection.updateOne(
                { username },
                { $set: { failedAttempts } }
            );

            return res.status(401).send("Invalid password");
        }

        // Reset failed attempts on successful login
        await collection.updateOne(
            { username },
            { $set: { failedAttempts: 0, lockUntil: null } }
        );

        // Identify user role (admin or user)
        const role = user.role || "user"; // Default to "user" if role is not set


        const JWT_SECRET = process.env.JWT_SECRET;
        if (!JWT_SECRET) {
            throw new Error("JWT_SECRET is not defined in environment variables.");
        }

        // Generate token
        const token = jwt.sign(
            { user_id: user.user_id, username: user.username, role },
            JWT_SECRET, // Use the environment variable
            { expiresIn: '1h' }
        );

        res.status(200).json({
            message: "Login successful",
            token,
            role // Include role in the response
        });
    } catch (error) {
        console.error("Error in login route:", error);
        res.status(500).send("Error logging in");
    }
});



// Middleware to verify token and check for admin role
const verifyAdmin = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract token from Authorization header

    if (!token) {
        return res.status(401).json({ message: "No token provided" });
    }

    try {
        // Verify the JWT token
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Use the same secretKey you used to sign the JWT

        // Check if the user has the admin role
        if (decoded.role !== 'admin') {
            return res.status(403).json({ message: "Access denied: Admins only" });
        }

        // If admin, allow the request to continue
        req.user = decoded; // Optionally attach the decoded token to the request
        next(); // Continue to the next middleware or route handler
    } catch (error) {
        return res.status(401).json({ message: "Invalid token" });
    }
};

// Middleware to verify token and check if the role is 'user'
const verifyUser = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract token
    if (!token) {
        return res.status(401).json({ message: "No token provided" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== 'user') {
            return res.status(403).json({ message: "Access denied: Users only" });
        }

        req.user = decoded; // Attach user details to request
        next();
    } catch (error) {
        console.error("Error in verifyUser middleware:", error);
        return res.status(401).json({ message: "Invalid token" });
    }
};


// Middleware to verify the token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).send("Token is required");
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send("Invalid or expired token");
        }

        req.user = decoded;
        next();
    });
};

const checkRole = (role) => {
    return (req, res, next) => {
        const userRole = req.user?.role; // Assuming role is part of the decoded token payload
        if (userRole === role) {
            return next();
        }
        return res.status(403).send("Forbidden: You do not have the required role.");
    };
};


// Example protected route
app.get('/protectedRoute', verifyToken, (req, res) => {
    res.status(200).send(`Hello ${req.user.username}, this is a protected route.`);
});


app.post('/createItem', verifyAdmin, async (req, res) => {
    try {
        const { item_id, name, description, type, attributes, rarity } = req.body;
        const database = client.db('Cluster');
        const collection = database.collection('items');

        // Basic validation
        if (!item_id || !name || !description || !type || !attributes || !rarity) {
            return res.status(400).send("Missing required fields: item_id, name, description, type, attributes, or rarity");
        }

        const item = {
            item_id,
            name,
            description,
            type,
            attributes,
            rarity
        };

        // Insert the item into the database
        await collection.insertOne(item);
        res.status(201).send("Item created successfully");
    } catch (error) {
        console.error("Error in createItem route:", error);
        res.status(500).send("Error creating item");
    }
});


app.post('/createMonster', verifyAdmin, async (req, res) => {
    try {
        const { monster_id, name, attributes, location } = req.body;
        const database = client.db('Cluster');
        const collection = database.collection('monsters');

        // Basic validation
        if (!monster_id || !name || !attributes || !location) {
            return res.status(400).send("Missing required fields: monster_id, name, attributes, or location");
        }

        const monster = {
            monster_id,
            name,
            attributes,
            location
        };

        // Insert the monster into the database
        await collection.insertOne(monster);
        res.status(201).send("Monster created successfully");
    } catch (error) {
        console.error("Error in createMonster route:", error);
        res.status(500).send("Error creating monster");
    }
});

app.post('/createTransaction', verifyUser, async (req, res) => {
    try {
        const { transaction_id, user_id, item_id, transaction_type, amount, date } = req.body;

        if (req.user.user_id !== user_id) {
            return res.status(403).json({ message: "You can only create transactions for your own account." });
        }

        const database = client.db('Cluster');
        const usersCollection = database.collection('users');
        const itemsCollection = database.collection('items');
        const transactionsCollection = database.collection('transactions');

        // Check if user exists
        const userExists = await usersCollection.findOne({ user_id });
        if (!userExists) {
            return res.status(404).send(`User with ID ${user_id} does not exist.`);
        }

        // Check if item exists
        const itemExists = await itemsCollection.findOne({ item_id });
        if (!itemExists) {
            return res.status(404).send(`Item with ID ${item_id} does not exist.`);
        }

        // Insert the transaction
        const transaction = { transaction_id, user_id, item_id, transaction_type, amount, date };
        await transactionsCollection.insertOne(transaction);

        res.status(201).send("Transaction created successfully");
    } catch (error) {
        console.error("Error in createTransaction route:", error);
        res.status(500).send("Error creating transaction");
    }
});

app.post('/createWeapon', verifyAdmin, async (req, res) => {
    try {
        const { weapon_id, name, description, damage, type, attributes } = req.body;
        const database = client.db('Cluster');
        const collection = database.collection('weapons');

        // Basic validation
        if (!weapon_id || !name || !description || !damage || !type || !attributes) {
            return res.status(400).send("Missing required fields: weapon_id, name, description, damage, type, or attributes");
        }

        const weapon = {
            weapon_id,
            name,
            description,
            damage,
            type,
            attributes
        };

        // Insert the weapon into the database
        await collection.insertOne(weapon);
        res.status(201).send("Weapon created successfully");
    } catch (error) {
        console.error("Error in createWeapon route:", error);
        res.status(500).send("Error creating weapon");
    }
});

app.get('/', (req, res) => {
    res.send('Welcome to the API');
});

// Check if a user exists

app.get('/checkUser/:user_id', async (req, res) => {
    try {
        const { user_id } = req.params;
        const userExists = await existingUser(client, user_id);

        if (userExists) {
            res.status(200).send(`User with ID ${user_id} exists.`);
        } else {
            res.status(404).send(`User with ID ${user_id} does not exist.`);
        }
    } catch (error) {
        console.error("Error checking user existence:", error);
        res.status(500).send("Error checking user existence");
    }
});



// Check if an item exists
app.get('/checkItem/:item_id', async (req, res) => {
    try {
        const { item_id } = req.params;
        const itemExists = await existingItem(client, item_id);

        if (itemExists) {
            res.status(200).send(`Item with ID ${item_id} exists.`);
        } else {
            res.status(404).send(`Item with ID ${item_id} does not exist.`);
        }
    } catch (error) {
        console.error("Error checking item existence:", error);
        res.status(500).send("Error checking item existence");
    }
});

// Check if a monster exists
app.get('/checkMonster/:monster_id', async (req, res) => {
    try {
        const { monster_id } = req.params;
        const monsterExists = await existingMonster(client, monster_id);

        if (monsterExists) {
            res.status(200).send(`Monster with ID ${monster_id} exists.`);
        } else {
            res.status(404).send(`Monster with ID ${monster_id} does not exist.`);
        }
    } catch (error) {
        console.error("Error checking monster existence:", error);
        res.status(500).send("Error checking monster existence");
    }
});

// Check if a weapon exists
app.get('/checkWeapon/:weapon_id', async (req, res) => {
    try {
        const { weapon_id } = req.params;
        const weaponExists = await existingWeapon(client, weapon_id);

        if (weaponExists) {
            res.status(200).send(`Weapon with ID ${weapon_id} exists.`);
        } else {
            res.status(404).send(`Weapon with ID ${weapon_id} does not exist.`);
        }
    } catch (error) {
        console.error("Error checking weapon existence:", error);
        res.status(500).send("Error checking weapon existence");
    }
});

app.get('/findUserByUsername/:username', async (req, res) => {
    try {
        const { username } = req.params;
        console.log(`Looking for user: ${username}`);  // Log the username to see what it's searching for

        // Get the database and collection
        const database = client.db('Cluster');
        const collection = database.collection('users');

        // Find the user by username using case-insensitive regex
        const user = await collection.findOne({ username: { $regex: new RegExp(username, 'i') } });

        if (user) {
            console.log(`User found: ${JSON.stringify(user)}`);  // Log the user data if found
            res.status(200).json(user);
        } else {
            console.log(`User with username "${username}" not found.`);
            res.status(404).send(`User with username "${username}" not found.`);
        }
    } catch (error) {
        console.error("Error finding user by username:", error);
        res.status(500).send("Error finding user by username");
    }
});


// Route to find a user by ID
app.get('/findUserById/:user_id', async (req, res) => {
    try {
        const { user_id } = req.params;
        console.log(`Looking for user with ID: ${user_id}`);  // Log the user ID to see what it's searching for

        // Get the database and collection
        const database = client.db('Cluster');
        const collection = database.collection('users');

        // Find the user by user_id
        const user = await collection.findOne({ user_id });

        if (user) {
            console.log(`User found: ${JSON.stringify(user)}`);  // Log the user data if found
            res.status(200).json(user);
        } else {
            console.log(`User with ID "${user_id}" not found.`);
            res.status(404).send(`User with ID "${user_id}" not found.`);
        }
    } catch (error) {
        console.error("Error finding user by ID:", error);
        res.status(500).send("Error finding user by ID");
    }
});


// Monsterslain route
app.post('/monsterslain', verifyUser, async (req, res) => {
    try {
        const { user_id, monster_id } = req.body;

        if (req.user.user_id !== user_id) {
            return res.status(403).json({ message: "You can only update your own profile." });
        }

        const user = await client.db('Cluster').collection('users').findOne({ user_id });

        if (!user) {
            return res.status(404).send(`User with ID "${user_id}" not found.`);
        }

        const updatedProfile = await monsterslain(client, user_id, monster_id);

        if (!updatedProfile) {
            return res.status(500).send("Error updating profile after monster slain.");
        }

        res.status(200).json(updatedProfile);
    } catch (error) {
        console.error("Error in monsterslain route:", error);
        res.status(500).send(`Error processing monster slain: ${error.message}`);
    }
});

// Delete user route
app.delete('/deleteUser/:user_id', verifyAdmin, async (req, res) => {
    try {
        const { user_id } = req.params;

        if (!user_id) {
            return res.status(400).send("Missing required field: user_id");
        }

        // Ensure the user exists before attempting to delete
        const database = client.db('Cluster');
        const collection = database.collection('users');

        const user = await collection.findOne({ user_id });
        if (!user) {
            return res.status(404).send(`User with ID "${user_id}" not found.`);
        }

        // Proceed with deleting the user
        const result = await collection.deleteOne({ user_id });

        if (result.deletedCount === 1) {
            return res.status(200).send("User deleted successfully");
        } else {
            return res.status(500).send("Error deleting user");
        }
    } catch (error) {
        console.error("Error in deleteUser route:", error);
        res.status(500).send("Error deleting user");
    }
});



// Report user route
app.post('/reportUser', verifyUser, async (req, res) => {
    try {
        const { reporter_id, reported_user_id, reason } = req.body;

        if (req.user.user_id !== reporter_id) {
            return res.status(403).json({ message: "You can only report users as yourself." });
        }

        const database = client.db('Cluster');
        const usersCollection = database.collection('users');

        // Check if reported user exists
        const reportedUser = await usersCollection.findOne({ user_id: reported_user_id });
        if (!reportedUser) {
            return res.status(404).send(`Reported user with ID ${reported_user_id} does not exist.`);
        }

        // Insert the report
        const reportsCollection = database.collection('reports');
        const report = { reporter_id, reported_user_id, reason, date: new Date() };
        await reportsCollection.insertOne(report);

        res.status(201).send("Report submitted successfully");
    } catch (error) {
        console.error("Error in reportUser route:", error);
        res.status(500).send("Error submitting report");
    }
});

// All Find Functions (Users only)
app.get('/findUserByUsername/:username', verifyUser, async (req, res) => {
    try {
        const { username } = req.params;

        const database = client.db('Cluster');
        const collection = database.collection('users');

        const user = await collection.findOne({ username: { $regex: new RegExp(username, 'i') } });

        if (user) {
            res.status(200).json(user);
        } else {
            res.status(404).send(`User with username "${username}" not found.`);
        }
    } catch (error) {
        console.error("Error finding user by username:", error);
        res.status(500).send("Error finding user by username");
    }
});

// Leaderboard route
app.get('/leaderboard', async (req, res) => {
    try {
        const leaderboard = await viewLeaderboard(client);
        res.status(200).json(leaderboard);
    } catch (error) {
        console.error("Error in /leaderboard route:", error);
        res.status(500).send("Error fetching leaderboard");
    }
});

// View User by Admin Route
app.get('/viewUserByAdmin/:user_id', verifyAdmin, async (req, res) => {
    try {
        const { user_id } = req.params;

        const user = await viewUserByAdmin(client, user_id);

        if (!user) {
            return res.status(404).send(`User with ID ${user_id} not found.`);
        }

        res.status(200).json(user);
    } catch (error) {
        console.error("Error in viewUserByAdmin route:", error);
        res.status(500).send("Error fetching user by admin.");
    }
});

