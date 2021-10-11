const express = require('express')
const router = express.Router()
const auth = require('../../middleware/auth')
const { check, validationResult } = require('express-validator')
const config = require('config')
const jwd = require('jsonwebtoken')
const bcrypt = require('bcryptjs')

// @route   GET api/auth
// @desc    Test route
// @access  Public
router.get('/', auth, async(req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password')
        res.json(user)
    } catch (err) {
        console.log(err.massage);
        res.status(500).send('Server Error')
    }
})

// @route   POST api/auth
// @desc    Authenticate user & get token
// @access  Public
router.post('/', //Router-level middleware
    [
        check('email', 'Please include a valid email').isEmail(),
        check('password', 'Password is required').exists()
    ],
    async(req, res) => {
        const err = validationResult(req)
        if (!err.isEmpty()) {
            return res.status(400).json({ err: err.array() })
        }

        const { email, password } = req.body

        try {
            //see if user exists
            let user = await User.findOne({ email })

            if (!user) {
                return res.status(400).json({ errors: [{ msg: 'Invalid Credentials' }] })
            }

            const isMatch = await bcrypt.compare(password, user.password)
            if (!isMatch) {
                return res.status(400).json({ errors: [{ msg: 'Invalid Credentials' }] })
            }

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