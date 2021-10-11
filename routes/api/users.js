const express = require('express')
const router = express.Router()
const gravatar = require('gravatar')
const bcrypt = require('bcryptjs')
const config = require('config')
const jwd = require('jsonwebtoken')
const { check, validationResult } = require('express-validator')
const User = require('../../models/User')

// @route   POST api/users
// @desc    Register user
// @access  Public
router.post('/', //Router-level middleware
    [
        check('name', 'Name is required').not().isEmpty(),
        check('email', 'Please include a valid email').isEmail(),
        check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 })
    ],
    async(req, res) => {
        const err = validationResult(req)
        if (!err.isEmpty()) {
            return res.status(400).json({ err: err.array() })
        }

        const { name, email, password } = req.body

        try {
            //see if user exists
            let user = await User.findOne({ email })

            if (user) {
                return res.status(400).json({ errors: [{ msg: 'User already exists' }] })
            }

            //get user gravatar ..create new user
            const avatar = gravatar.url(email, { s: '200', r: 'pg', d: 'mm' })

            user = new User({
                name,
                email,
                avatar,
                password
            })

            //Encrypt password ..hash password
            const salt = await bcrypt.genSalt(10)
            user.password = await bcrypt.hash(password, salt)

            await user.save() //save user in DB

            //Return jsonwebtoken   
            const payload = { //the payload which include userID
                user: {
                    id: user.id
                }
            }

            jwd.sign( //sign the token pass and the payload pass
                payload, config.get('jwtSecret'), { expiresIn: 36000 }, //optional but recommend
                (err, token) => {
                    if (err) throw err
                    res.json({ token }) //if have no err, send that token to the client
                }
            )
        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server error')
        }

    })

module.exports = router