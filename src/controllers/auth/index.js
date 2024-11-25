const Joi = require("joi");
const express = require("express");

const BaseController = require("../base");
const UserModel = require("../../models/user");
const { checkPassword, encryptPassword } = require("../../helpers/bcrypt");
const { createToken } = require("../../helpers/jwt");
const { authorize } = require("../../middlewares/authorization");
const { getAuth, signInWithCredential, GoogleAuthProvider } = require("firebase/auth");
const router = express.Router();

const user = new UserModel();

const signUpSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string()
    .min(8)
    .required()
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})/)
    .messages({
      "string.min": `Password must length must be at least {#limit} 
        characters long`,
      "string.pattern.base": `Password must have at least 1 uppercase, 
        1 lowercase, 1 number, and 1 special character (i.e. !@#$%^&*)`,
    }),
  fullname: Joi.string(),
});

const signInSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

class AuthController extends BaseController {
  constructor(model) {
    super(model);
    router.post("/signin", this.validation(signInSchema), this.signIn);
    router.post("/signup", this.validation(signUpSchema), this.signUp);
    router.post("/googleSignIn", this.googleSignIn);
    router.get('/whoami', authorize, this.whoAmI)
  }

  signIn = async (req, res, next) => {
    try {
      const { email, password } = req.body;
      const user = await this.model.getOne({ where: { email } });

      if (!user) return next(new ValidationError("Invalid email or password"));

      const isMatch = await checkPassword(password, user.password);

      if (!isMatch)
        return next(new ValidationError("Invalid email or password"));

      const token = createToken({
        id: user.id,
      });

      return res.status(200).json(
        this.apiSend({
          code: 200,
          status: "success",
          message: "Sign in successfully",
          data: {
            user: {
              ...user,
              id: undefined,
              password: undefined,  // Do not return password in response
            },
            token,
          },
        })
      );
    } catch (e) {
      next(new ServerError(e));
    }
  };

  signUp = async (req, res, next) => {
    try {
      const { email, password, fullname } = req.body;
      const user = await this.model.getOne({ where: { email } });

      if (user) return next(new ValidationError("Email already exist!"));

      const newUser = await this.model.set({
        email,
        password: await encryptPassword(password),
        fullname,
        roleId: 3,
        provider: 'local',  // Set provider to local for normal signup
      });

      return res.status(200).json(
        this.apiSend({
          code: 200,
          status: "success",
          message: "Sign up successfully",
          data: {
            user: {
              ...newUser,
              id: undefined,
              password: undefined,  // Do not return password in response
            },
          },
        })
      );
    } catch (e) {
      next(new ServerError(e));
    }
  };

  whoAmI = async (req, res, next) => {
    return res.status(200).json(
      this.apiSend({
        code: 200,
        status: "success",
        message: "Get user successfully",
        data: {
          user: req.user,
        },
      })
    );
  };

  googleSignIn = async (req, res, next) => {
    const id_token = req.body.idToken;
    const credential = GoogleAuthProvider.credential(id_token);

    const auth = getAuth();
    try {
      // Sign in with Google credentials
      const signIn = await signInWithCredential(auth, credential);
      let user = await this.model.getOne({ where: { email: signIn.user.email } });

      // If user exists and provider is 'local', update provider to 'google'
      if (user && user.provider === 'local') {
        user = await this.model.update(user.id, {
          provider: 'google',  // Update provider to google
          googleId: signIn.user.uid,  // Store the googleId from Firebase
        });
      }

      // If no user exists, create a new user with Google credentials
      if (!user) {
        user = await this.model.set({
          email: signIn.user.email,
          password: null,  // No password needed for Google users
          fullname: signIn.user.displayName,
          provider: 'google',  // Set provider to google
          googleId: signIn.user.uid,  // Store googleId in database
          avatar: signIn.user.photoURL,
          roleId: 3,
        });
      }

      // Create JWT token
      const token = createToken({ id: user.id });

      return res.status(200).json(
        this.apiSend({
          code: 200,
          status: "success",
          message: "Sign in with Google successfully",
          data: {
            user: {
              ...user,
              password: undefined,  // Do not return password in response
            },
            token,
          },
        })
      );
    } catch (e) {
      // Handle errors
      console.error("Google sign-in error:", e);
      next(new ServerError(e));
    }
  };
}

new AuthController(user);

module.exports = router;
