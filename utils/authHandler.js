let jwt = require('jsonwebtoken')
let userController = require('../controllers/users')

function normalizeRoleName(roleName) {
    let value = String(roleName || '').toLowerCase();
    if (value === 'moderator') {
        return 'mod';
    }
    if (value === 'administrator') {
        return 'admin';
    }
    return value;
}

module.exports = {
    checkLogin: async function (req, res, next) {
        try {
            let token
            if (req.cookies.token) {
                token = req.cookies.token
            } else {
                token = req.headers.authorization;
                if (!token || !token.startsWith('Bearer ')) {
                    return res.status(401).send({ message: 'ban chua dang nhap' })
                }
                token = token.split(' ')[1];
            }

            let result = jwt.verify(token, 'secret');
            if (result && result.exp * 1000 > Date.now()) {
                req.userId = result.id;
                return next();
            }
            return res.status(401).send({ message: 'ban chua dang nhap' })
        } catch (error) {
            return res.status(401).send({ message: 'ban chua dang nhap' })
        }
    },
    checkRole: function (...requiredRole) {
        let normalizedRequiredRole = requiredRole.map(function (role) {
            return normalizeRoleName(role);
        });

        return async function (req, res, next) {
            let userId = req.userId;
            let user = await userController.FindUserById(userId);
            if (!user || !user.role || !user.role.name) {
                return res.status(403).send({ message: 'ban khong co quyen' });
            }

            let currentRole = normalizeRoleName(user.role.name);
            if (normalizedRequiredRole.includes(currentRole)) {
                return next();
            }
            return res.status(403).send({ message: 'ban khong co quyen' });
        }
    }
}