async function viewLeaderboard(client) {
    try {
        const database = client.db('Cluster');
        const usersCollection = database.collection('users');

        const leaderboard = await usersCollection.find()
            .sort({ 'profile.experience': -1 }) // Sort by experience in descending order
            .limit(10) // Limit to top 10 users
            .toArray();

        // Format the response to include only relevant details
        const formattedLeaderboard = leaderboard.map(user => ({
            user_id: user.user_id,
            username: user.username,
            experience: user.profile.experience,
            level: user.profile.level,
        }));

        return formattedLeaderboard;
    } catch (error) {
        console.error("Error in viewLeaderboard:", error);
        throw new Error('Error fetching leaderboard');
    }
}

async function viewUserByAdmin(client, user_id) {
    try {
        const database = client.db('Cluster');
        const collection = database.collection('users');

        const user = await collection.findOne({ user_id });
        if (!user) {
            throw new Error('User not found');
        }

        return user;
    } catch (error) {
        console.error("Error in viewUserByAdmin:", error);
        throw new Error('Error fetching user by admin');
    }
}

module.exports = {
    viewLeaderboard,
    viewUserByAdmin
};
