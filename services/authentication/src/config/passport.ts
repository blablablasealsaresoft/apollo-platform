import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as MicrosoftStrategy } from 'passport-microsoft';
import { Strategy as GitHubStrategy } from 'passport-github2';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import { config, database, UserRole, ClearanceLevel, generateId } from '@apollo/shared';

// JWT Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: config.jwt.secret,
};

passport.use(
  new JwtStrategy(jwtOptions, async (payload, done) => {
    try {
      const result = await database.query(
        `SELECT
          id, email, username, first_name as "firstName", last_name as "lastName",
          role, clearance_level as "clearanceLevel",
          is_active as "isActive", is_mfa_enabled as "isMfaEnabled"
        FROM users WHERE id = $1 AND is_active = true`,
        [payload.userId],
      );

      if (result.rows.length === 0) {
        return done(null, false);
      }

      return done(null, result.rows[0]);
    } catch (error) {
      return done(error, false);
    }
  }),
);

// Google OAuth Strategy
if (config.oauth.google.clientId && config.oauth.google.clientSecret) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: config.oauth.google.clientId,
        clientSecret: config.oauth.google.clientSecret,
        callbackURL: `${config.services.auth}/api/oauth/google/callback`,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value;
          if (!email) {
            return done(new Error('No email provided by Google'), false);
          }

          // Check if user exists
          let result = await database.query('SELECT * FROM users WHERE email = $1', [email]);

          if (result.rows.length > 0) {
            // User exists
            return done(null, result.rows[0]);
          }

          // Create new user
          const userId = generateId();
          result = await database.query(
            `INSERT INTO users (
              id, email, username, first_name, last_name,
              role, clearance_level, is_active, oauth_provider, oauth_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *`,
            [
              userId,
              email,
              email.split('@')[0],
              profile.name?.givenName || '',
              profile.name?.familyName || '',
              UserRole.VIEWER,
              ClearanceLevel.UNCLASSIFIED,
              true,
              'google',
              profile.id,
            ],
          );

          return done(null, result.rows[0]);
        } catch (error) {
          return done(error as Error, false);
        }
      },
    ),
  );
}

// Microsoft OAuth Strategy
if (config.oauth.microsoft.clientId && config.oauth.microsoft.clientSecret) {
  passport.use(
    new MicrosoftStrategy(
      {
        clientID: config.oauth.microsoft.clientId,
        clientSecret: config.oauth.microsoft.clientSecret,
        callbackURL: `${config.services.auth}/api/oauth/microsoft/callback`,
        scope: ['user.read'],
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value;
          if (!email) {
            return done(new Error('No email provided by Microsoft'), false);
          }

          // Check if user exists
          let result = await database.query('SELECT * FROM users WHERE email = $1', [email]);

          if (result.rows.length > 0) {
            return done(null, result.rows[0]);
          }

          // Create new user
          const userId = generateId();
          result = await database.query(
            `INSERT INTO users (
              id, email, username, first_name, last_name,
              role, clearance_level, is_active, oauth_provider, oauth_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *`,
            [
              userId,
              email,
              email.split('@')[0],
              profile.name?.givenName || '',
              profile.name?.familyName || '',
              UserRole.VIEWER,
              ClearanceLevel.UNCLASSIFIED,
              true,
              'microsoft',
              profile.id,
            ],
          );

          return done(null, result.rows[0]);
        } catch (error) {
          return done(error as Error, false);
        }
      },
    ),
  );
}

// GitHub OAuth Strategy
if (config.oauth.github.clientId && config.oauth.github.clientSecret) {
  passport.use(
    new GitHubStrategy(
      {
        clientID: config.oauth.github.clientId,
        clientSecret: config.oauth.github.clientSecret,
        callbackURL: `${config.services.auth}/api/oauth/github/callback`,
        scope: ['user:email'],
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value;
          if (!email) {
            return done(new Error('No email provided by GitHub'), false);
          }

          // Check if user exists
          let result = await database.query('SELECT * FROM users WHERE email = $1', [email]);

          if (result.rows.length > 0) {
            return done(null, result.rows[0]);
          }

          // Create new user
          const userId = generateId();
          const [firstName, ...lastNameParts] = (profile.displayName || email.split('@')[0]).split(' ');
          result = await database.query(
            `INSERT INTO users (
              id, email, username, first_name, last_name,
              role, clearance_level, is_active, oauth_provider, oauth_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *`,
            [
              userId,
              email,
              profile.username || email.split('@')[0],
              firstName,
              lastNameParts.join(' ') || '',
              UserRole.VIEWER,
              ClearanceLevel.UNCLASSIFIED,
              true,
              'github',
              profile.id,
            ],
          );

          return done(null, result.rows[0]);
        } catch (error) {
          return done(error as Error, false);
        }
      },
    ),
  );
}

export default passport;
