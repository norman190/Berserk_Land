const createUser = async (client, user_id, username, password, email) => {
    try {
        const database = client.db('Cluster');
        const collection = database.collection('users');

        const user = {
            user_id,
            username,
            password,
            email,
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

        await collection.insertOne(user);
        console.log("User created successfully");
    } catch (error) {
        console.error("Error creating user:", error);
        throw error;
    }
};

const createItem = async (client, item_id, name, description, type, attributes, rarity) => {
    try {
        const database = client.db('Cluster');
        const collection = database.collection('items');

        const item = {
            item_id,
            name,
            description,
            type,
            attributes,
            rarity
        };

        await collection.insertOne(item);
        console.log("Item created successfully");
    } catch (error) {
        console.error("Error creating item:", error);
        throw error;
    }
};

const createMonster = async (client, monster_id, name, attributes, location, experience) => {
    try {
        const database = client.db('Cluster');
        const collection = database.collection('monsters');

        const monster = {
            monster_id,
            name,
            attributes,
            location,
            experience  // Add experience here for each monster
        };

        await collection.insertOne(monster);
        console.log("Monster created successfully");
    } catch (error) {
        console.error("Error creating monster:", error);
        throw error;
    }
};

const createTransaction = async (client, transaction_id, user_id, item_id, transaction_type, amount, date) => {
    try {
        const database = client.db('Cluster');
        const usersCollection = database.collection('users');
        const itemsCollection = database.collection('items');
        const transactionsCollection = database.collection('transactions');

        // Check if the user exists
        const userExists = await usersCollection.findOne({ user_id });
        if (!userExists) {
            throw new Error(`User with ID ${user_id} does not exist.`);
        }

        // Check if the item exists
        const itemExists = await itemsCollection.findOne({ item_id });
        if (!itemExists) {
            throw new Error(`Item with ID ${item_id} does not exist.`);
        }

        // Create the transaction if both user and item exist
        const transaction = {
            transaction_id,
            user_id,
            item_id,
            transaction_type,
            amount,
            date
        };

        await transactionsCollection.insertOne(transaction);
        console.log("Transaction created successfully");
    } catch (error) {
        console.error("Error creating transaction:", error.message);
        throw error;
    }
};


const createWeapon = async (client, weapon_id, name, description, damage, type, attributes) => {
    try {
        const database = client.db('Cluster');
        const collection = database.collection('weapons');

        const weapon = {
            weapon_id,
            name,
            description,
            damage,
            type,
            attributes
        };

        await collection.insertOne(weapon);
        console.log("Weapon created successfully");
    } catch (error) {
        console.error("Error creating weapon:", error);
        throw error;
    }
};

module.exports = {
    createUser,
    createItem,
    createMonster,
    createTransaction,
    createWeapon
};
