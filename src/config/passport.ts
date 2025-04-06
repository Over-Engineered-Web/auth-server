import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import User, { IUser } from '../models/User';
import { Request } from 'express';
import { logger } from '../utils/logger';

// Environment variables should be loaded from a .env file using dotenv
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Configure passport with strategies
export const configurePassport = (): void => {
  // Serialize user to store in session
  passport.serializeUser((user: Express.User, done) => {
    done(null, (user as IUser).id);
  });

  // Deserialize user from session
  passport.deserializeUser(async (id: string, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (error) {
      done(error);
    }
  });

  // Local strategy for email/password authentication
  passport.use(
    new LocalStrategy(
      {
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true,
      },
      async (req: Request, email: string, password: string, done) => {
        try {
          // Find the user by email
          const user = await User.findOne({ email: email.toLowerCase() });
          
          // User not found
          if (!user) {
            logger.warn(`Login attempt for non-existent user: ${email}`);
            return done(null, false, { message: 'Invalid email or password' });
          }
          
          // Check if account is locked
          if (user.lockUntil && user.lockUntil > new Date()) {
            logger.warn(`Attempted login to locked account: ${email}`);
            return done(null, false, { 
              message: 'Account is temporarily locked due to too many failed login attempts. Try again later.'
            });
          }
          
          // Verify the password
          const isMatch = await user.comparePassword(password);
          
          // Password doesn't match
          if (!isMatch) {
            logger.warn(`Failed login attempt for user: ${email}`);
            await user.incrementLoginAttempts();
            return done(null, false, { message: 'Invalid email or password' });
          }
          
          // Check if email is verified (if required)
          if (!user.isEmailVerified) {
            logger.info(`Login attempt on unverified account: ${email}`);
            return done(null, false, { message: 'Please verify your email before logging in' });
          }
          
          // Reset login attempts on successful login
          await user.resetLoginAttempts();
          
          // Update last login time
          user.lastLogin = new Date();
          await user.save();
          
          logger.info(`User logged in: ${email}`);
          return done(null, user);
        } catch (error) {
          logger.error(`Authentication error: ${(error as Error).message}`);
          return done(error);
        }
      }
    )
  );

  // JWT strategy for token authentication
  passport.use(
    new JwtStrategy(
      {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: JWT_SECRET,
      },
      async (jwtPayload, done) => {
        try {
          // Find the user by ID from JWT payload
          const user = await User.findById(jwtPayload.id);
          
          if (!user) {
            return done(null, false);
          }
          
          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );
};