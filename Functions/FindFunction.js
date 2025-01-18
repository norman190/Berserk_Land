const findUserByUsername = async (client, username) => {
    try {
        const database = client.db('Cluster');
        const collection = database.collection('users');

        const user = await collection.findOne({ username });
        return user; // Returns the user document if found, otherwise null
    } catch (error) {
        console.error("Error finding user by username:", error);
        throw error;
    }
};

const findUserById = async (client, user_id) => {
    try {
        const database = client.db('Cluster');
        const collection = database.collection('users');

        const user = await collection.findOne({ user_id });
        return user; // Returns the user document if found, otherwise null
    } catch (error) {
        console.error("Error finding user by ID:", error);
        throw error;
    }
};

module.exports = {
    findUserByUsername,
    findUserById
};
