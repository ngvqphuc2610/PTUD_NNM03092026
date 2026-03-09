let userModel = require('../schemas/users')
let bcrypt = require('bcrypt')
module.exports = {
    CreateAnUser: async function (username, password, email, role,
        avatarUrl, fullName, status, loginCount
    ) {
        let newUser = new userModel({
            username: username,
            password: password,
            email: email,
            role: role,
            avatarUrl: avatarUrl,
            fullName: fullName,
            status: status,
            loginCount: loginCount
        })
        await newUser.save();
        return newUser;
    },
    QueryByUserNameAndPassword: async function (username, password) {
        let getUser = await userModel.findOne({ username: username });
        if (!getUser) {
            return false;
        }
        let isMatch = bcrypt.compareSync(password, getUser.password);
        if (!isMatch) {
            return false;
        }
        return getUser;
    },
    FindUserById: async function (id) {
        return await userModel.findOne({
            _id: id,
            isDeleted: false
        }).populate('role')
    },
    ChangePassword: async function (userId, oldPassword, newPassword) {
        let user = await userModel.findOne({ _id: userId, isDeleted: false });
        if (!user) {
            throw new Error('user not found');
        }

        let isMatch = bcrypt.compareSync(oldPassword, user.password);
        if (!isMatch) {
            throw new Error('old password is incorrect');
        }

        user.password = newPassword;
        await user.save();
        return true;
    }
}