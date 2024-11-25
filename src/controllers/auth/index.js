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
  fullname: Joi.string()
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
              password: undefined,
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
        roleId: 3
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
              password: undefined,
            },
          },
        })
      );
    } catch (e) {
      next(new ServerError(e));
    }
  };

  whoAmI = async(req, res, next) => {
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
  }

  googleSignIn = async (req, res, next) => {
    const id_token = req.body.idToken;  // Mendapatkan ID token dari request body
    const credential = GoogleAuthProvider.credential(id_token);  // Membuat kredensial Google menggunakan ID token
  
    const auth = getAuth();
    try {
      // Melakukan sign-in menggunakan kredensial Google
      const signIn = await signInWithCredential(auth, credential);
  
      // Cek apakah pengguna sudah ada di database dengan email yang sama
      let user = await this.model.getOne({ where: { email: signIn.user.email } });
  
      if (user) {
        // Kasus 1: Pengguna sudah terdaftar dengan akun lokal (provider 'local')
        if (user.provider === 'local') {
          // Update data pengguna agar terhubung dengan Google
          user = await this.model.update(user.id, {
            provider: 'google',        // Ubah provider menjadi 'google'
            googleId: signIn.user.uid, // Simpan UID Google pengguna
          });
        }
        // Kasus 2: Pengguna sudah terdaftar dengan akun Google (tidak perlu perubahan apa pun)
        // Di sini, kita hanya mengembalikan token dan data pengguna tanpa perubahan data.
      } else {
        // Kasus 3: Pengguna baru, buat akun baru
        user = await this.model.set({
          email: signIn.user.email,
          password: null,              // Password tidak diperlukan karena login dengan Google
          fullname: signIn.user.displayName, // Nama lengkap dari akun Google
          provider: 'google',          // Tandai pengguna menggunakan provider Google
          googleId: signIn.user.uid,   // Simpan UID Google untuk identifikasi
          avatar: signIn.user.photoURL, // Avatar pengguna dari Google (opsional)
          roleId: 3                    // Atur role pengguna (misal '3' untuk pengguna umum)
        });
      }
  
      // Buat token JWT untuk pengguna yang baru atau yang sudah ada
      const token = createToken({
        id: user.id,  // Gunakan ID pengguna untuk membuat token
      });
  
      // Kirimkan respons dengan data pengguna dan token
      return res.status(200).json(
        this.apiSend({
          code: 200,
          status: "success",
          message: "Sign in with Google successfully",
          data: {
            user: {
              ...user,
              password: undefined,  // Jangan kirimkan password pengguna dalam response
            },
            token,  // Token JWT untuk autentikasi
          },
        })
      );
    } catch (e) {
      // Tangani error jika terjadi masalah saat proses sign-in
      next(new ServerError(e));
    }
  }
}  

new AuthController(user);

module.exports = router;
