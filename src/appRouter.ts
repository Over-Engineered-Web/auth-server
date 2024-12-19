// src/routes/index.ts
import { Router, Express } from 'express';
import { privateRoute, publicRoute, createHandler } from './trpc';
import { db } from './db';
import { eq } from 'drizzle-orm';
import { userTable } from './schema';

// Create separate routers for different features
const createDoThingRouter = () => {
  const router = Router();

  router.post(
    '/',
    createHandler(async (req, res) => {
      // Implementation of doThingQuery logic here
      // This would contain the actual business logic from the original doThingQuery
      const result = { success: true }; // Replace with actual logic
      res.json(result);
    })
  );

  return router;
};

const createMeRouter = () => {
  const router = Router();

  router.get(
    '/',
    privateRoute,
    createHandler(async (req, res) => {
      const user = await db.query.users.findFirst({
        where: eq(userTable.id, req.userId),
      });

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.json(user);
    } )
  );

  return router;
};

// API Routes setup
const createApiRouter = () => {
  const router = Router();

  // Mount feature routers
  router.use('/doThing', createDoThingRouter());
  router.use('/me', createMeRouter());

  return router;
};

// Main routes setup
export function setupRoutes(app: Express) {
  // API routes
  const apiRouter = createApiRouter();
  app.use('/api', apiRouter);

  // Health check endpoint
  app.get('/health', publicRoute, (req, res) => {
    res.json({ status: 'ok' });
  });

  // Catch-all for undefined routes
  app.use('*', (req, res) => {
    res.status(404).json({ error: 'Not Found' });
  });
}

// Types for request bodies and responses
export interface DoThingResponse {
  success: boolean;
  // Add other response fields as needed
}

export interface MeResponse {
  id: string;
  discordId: string;
  refreshToken?: number;
  // Add other user fields as needed
}
