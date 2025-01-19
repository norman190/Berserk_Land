const express = require('express');
const { MongoClient, ServerApiVersion } = require('mongodb');
const jwt = require('jsonwebtoken');
const JWT_SECRET = "020601"; 
const { createUser, createItem, createMonster, createTransaction, createWeapon } = require('./Functions/CreateFunction');
const { existingUser, existingItem, existingMonster, existingWeapon } = require('./Functions/ExistingFunction'); // Import the existing functions
const { findUserByUsername, findUserById } = require('./Functions/FindFunction'); // Import the find functions
const { monsterslain, deleteUser, reportUser } = require('./Functions/OtherFunction'); // Import the other functions 
const { viewLeaderboard, viewUserByAdmin } = require('./Functions/ViewFunction'); // Import the view functions

const app = express();
const port = process.env.port || 8080;


// Hardcoded MongoDB URI and JWT secret
const uri = "mongodb+srv://airel:airel123@cluster.yvryh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster";  // MongoDB connection string

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true
    }
});



async function connectToDatabase() {
    try {
        await client.connect();
        console.log("Connected to MongoDB");
        return client;
    } catch (error) {
        console.error("Error connecting to MongoDB:", error);
        process.exit(1); // Exit if the database connection fails
    }
}

// Middleware
app.use(express.json());

// Routes
app.get('/', (req, res) => {
    res.send('Welcome to the API');
});

app.post('/createUser', async (req, res) => {
    try {
        const { user_id, username, password, email, role = "user" } = req.body; // Default role is "user"
        const database = client.db('Cluster');
        const collection = database.collection('users');

        // Basic validation
        if (!user_id || !username || !password || !email) {
            return res.status(400).send("Missing required fields: user_id, username, password, or email");
        }

        // Check for duplicate user_id or username
        const existingUser = await collection.findOne({
            $or: [{ user_id }, { username }]
        });

        if (existingUser) {
            return res.status(409).send("User with the same user_id or username already exists");
        }

        const user = {
            user_id,
            username,
            password,
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

        // Verify the password
        if (user.password !== password) {
            return res.status(401).send("Invalid password");
        }

        // Identify user role (admin or user)
        const role = user.role || "user";  // Default to "user" if role is not set

        // Include the role in the token
        const token = jwt.sign(
            { user_id: user.user_id, username: user.username, role: role },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        // Send response with role information
        res.status(200).json({
            message: "Login successful",
            token,
            role  // Include role in the response
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
        const decoded = jwt.verify(token, '020601'); // Use the same secretKey you used to sign the JWT

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



// Middleware to verify the token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).send("Token is required");
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
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

app.post('/createTransaction', async (req, res) => {
    try {
        const { transaction_id, user_id, item_id, transaction_type, amount, date } = req.body;
        const database = client.db('Cluster');

        // Check if user exists
        const usersCollection = database.collection('users');
        const userExists = await usersCollection.findOne({ user_id });
        if (!userExists) {
            return res.status(404).send(`User with ID ${user_id} does not exist.`);
        }

        // Check if item exists
        const itemsCollection = database.collection('items');
        const itemExists = await itemsCollection.findOne({ item_id });
        if (!itemExists) {
            return res.status(404).send(`Item with ID ${item_id} does not exist.`);
        }

        // Insert the transaction
        const transactionsCollection = database.collection('transactions');
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
app.post('/monsterslain', async (req, res) => {
    try {
        const { user_id, monster_id } = req.body;

        // Log the incoming request body to inspect the data
        console.log("Request body:", req.body);

        if (!user_id || !monster_id) {
            return res.status(400).send("Missing required fields: user_id or monster_id");
        }

        const user = await client.db('Cluster').collection('users').findOne({ user_id });

        if (!user) {
            return res.status(404).send(`User with ID "${user_id}" not found.`);
        }

        console.log("User found:", user);

        // Call monsterslain and check the result
        const updatedProfile = await monsterslain(client, user_id, monster_id);

        if (!updatedProfile) {
            console.log("Failed to update profile for user_id:", user_id);  // Log failure case
            return res.status(500).send("Error updating profile after monster slain.");
        }

        // If updated profile is returned, send success response
        console.log("Updated profile:", updatedProfile);  // Log the updated profile
        res.status(200).json(updatedProfile);  // Return updated user profile
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
            res.status(200).send("User deleted successfully");
        } else {
            res.status(500).send("Error deleting user");
        }
    } catch (error) {
        console.error("Error in deleteUser route:", error);
        res.status(500).send("Error deleting user");
    }
});


// Report user route
app.get('/reportUser/:user_id', async (req, res) => {
    try {
        const { user_id } = req.params;

        if (!user_id) {
            return res.status(400).send("Missing required field: user_id");
        }

        // Fetch the user details from the database
        const user = await client.db('Cluster').collection('users').findOne({ user_id });

        if (!user) {
            return res.status(404).send(`User with ID "${user_id}" not found.`);
        }

        // Generate the enhanced report
        const report = {
            report_generated_at: new Date().toISOString(),
            user_report: {
                user_id: user.user_id,
                username: user.username,
                email: user.email,
                profile: user.profile,
                monsters_slain_count: user.monsters_slain.length,
                inventory_count: user.inventory.length,
                recent_activity: "No suspicious activity detected",  // This can be enhanced with real data
                report_status: "Report generated successfully"
            }
        };

        res.status(200).json(report);

    } catch (error) {
        console.error("Error in reportUser route:", error);
        res.status(500).send("Error generating user report");
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



// Connect to MongoDB and start the server
connectToDatabase().then(() => {
    app.listen(port, () => {
        console.log(`Server running on http://localhost:${port}`);
    });
}).catch(err => {
    console.error("Failed to connect to database:", err);
    process.exit(1);
});
///ssaadadada