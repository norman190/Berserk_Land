async function monsterslain(client, user_id, monster_id) {
    try {
        const db = client.db('Cluster');
        const usersCollection = db.collection('users');

        // Fetch the user's current profile
        const user = await usersCollection.findOne({ user_id });
        if (!user) {
            throw new Error(`User with ID "${user_id}" not found.`);
        }

        // Calculate the new experience
        const newExperience = user.profile.experience + 50;

        // Calculate the new level based on experience
        const newLevel = Math.floor(newExperience / 100) + 1;

        // Update the user's profile in the database
        const updateResult = await usersCollection.updateOne(
            { user_id },
            {
                $set: {
                    "profile.experience": newExperience,
                    "profile.level": newLevel,
                },
                $push: { monsters_slain: monster_id },
            }
        );

        console.log("Update result for monsters slain:", updateResult);

        // Check if the update succeeded
        if (updateResult.modifiedCount === 0) {
            throw new Error(`Failed to update the user's profile for user_id: ${user_id}`);
        }

        // Fetch the updated user profile
        const updatedUser = await usersCollection.findOne({ user_id });
        if (!updatedUser) {
            throw new Error(`Failed to retrieve updated profile for user_id: ${user_id}`);
        }

        console.log("Updated user profile:", updatedUser);
        return updatedUser;
    } catch (error) {
        console.error("Error in monsterslain function:", error);
        throw error; // Re-throw to handle in the route
    }
}


const deleteUser = async (client, user_id) => {
    try {
        const database = client.db('Cluster');
        const collection = database.collection('users');

        const result = await collection.deleteOne({ user_id });
        if (result.deletedCount === 0) {
            throw new Error('User not found');
        }

        console.log("User deleted successfully");
        return true; // Indicates successful deletion
    } catch (error) {
        console.error("Error deleting user:", error);
        throw error;
    }
};


module.exports = {
    monsterslain,
    deleteUser,
};
