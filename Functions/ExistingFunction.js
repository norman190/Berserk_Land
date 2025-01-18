const existingUser = async (client, user_id) => {
    try {
        const database = client.db('Cluster');
        const collection = database.collection('users');

        const userExists = await collection.findOne({ user_id });
        return !!userExists; // Returns true if user exists, false otherwise
    } catch (error) {
        console.error("Error checking existing user:", error);
        throw error;
    }
};

const existingItem = async (client, item_id) => {
    try {
        const database = client.db('Cluster');
        const collection = database.collection('items');

        const itemExists = await collection.findOne({ item_id });
        return !!itemExists; // Returns true if item exists, false otherwise
    } catch (error) {
        console.error("Error checking existing item:", error);
        throw error;
    }
};

const existingMonster = async (client, monster_id) => {
    try {
        const database = client.db('Cluster');
        const collection = database.collection('monsters');

        const monsterExists = await collection.findOne({ monster_id });
        return !!monsterExists; // Returns true if monster exists, false otherwise
    } catch (error) {
        console.error("Error checking existing monster:", error);
        throw error;
    }
};

const existingWeapon = async (client, weapon_id) => {
    try {
        const database = client.db('Cluster');
        const collection = database.collection('weapons');

        const weaponExists = await collection.findOne({ weapon_id });
        return !!weaponExists; // Returns true if weapon exists, false otherwise
    } catch (error) {
        console.error("Error checking existing weapon:", error);
        throw error;
    }
};

module.exports = {
    existingUser,
    existingItem,
    existingMonster,
    existingWeapon
};
