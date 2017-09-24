const mongoose = require("mongoose");
const User = mongoose.model('User');
const crypto = require('crypto');
const promisify = require('es6-promisify');
const mail = require("../handlers/mail");

const passport = require('passport');

exports.login = passport.authenticate('local', {
    failureRedirect : '/login',
    failureFlash : 'Failed Login!',
    successRedirect : '/',
    successFlash : 'You are now logged in!'
});

exports.logout = (req, res) => {
    req.logout();
    req.flash("success", "You are now logged out");
    res.redirect("/");
};

exports.isLoggedIn = (req, res, next) => {
    if (req.isAuthenticated()) {
        next();
        return;
    }
    req.flash('error', "Oops! You must be looged in to do that!");
    res.redirect("/login");
};

exports.forgot = async (req, res) => {
    const user = await User.findOne({
        email : req.body.email
    });

    if (!user) {
        req.flash("error", "No account with that email exists");
        return res.redirect("/login");
    }

    user.resetPasswordToken = crypto.randomBytes(28).toString('hex');
    user.resetPasswordExpires = Date.now() + 360000;
    await user.save();
    const resetURL = `http://${req.headers.host}/account/reset/${user.resetPasswordToken}`;
    //send email
    await mail.send({
        user,
        subject : "Password Reset",
        resetURL,
        filename: 'password-reset'
    });

    req.flash("success", "You have been emailed a password reset link. ");
    res.redirect("/login");
};

exports.reset = async (req, res) => {
    const user = await User.findOne({
        resetPasswordToken : req.params.token,
        resetPasswordExpires : {
            $gt : Date.now()
        }
    });
    if (!user) {
        req.flash("error", "Password reset is invalid or has expired");
        return res.redirect("/login");
    }
    res.render("reset", {
        title : "Reset your Password"
    })
};
exports.confirmedPasswords = (req, res, next) => {
    if (req.body.password === req.body['confirm-password']) {
        return next();
    }
    req.flash("error", "Password do not match!");
    req.redirect('back');
};

exports.update = async (req, res) => {
    const user = await User.findOne({
        resetPasswordToken : req.params.token,
        resetPasswordExpires : {
            $gt : Date.now()
        }
    });

    if (!user) {
        req.flash("error", "Password reset is invalid or has expired");
        return res.redirect("/login");
    }

    const setPassword = promisify(user.setPassword, user);
    await setPassword(req.body.password);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    const updatedUser = await user.save();
    await req.login(updatedUser);

    req.flash('success', "Nice! You passwod has been reset! You are now logged in!");
    res.redirect('/');


};
