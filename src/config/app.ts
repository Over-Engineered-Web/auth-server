import express, { Request, Response, NextFunction } from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import compression from 'compression';
import passport from 'passport';
import mongoSanitize from 'express-mongo-sanitize';
import { apiLimiter } from '../middleware/rateLimiter';
import { logger } from '../utils/logger';
import authRoutes from '../routes/authRoutes';
import { configurePassport } from './passport';

export const createApp = () => {
  const app = express();

  // Security headers middleware
  app.use(helmet());

  // Parse JSON request body
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: true }));

  // CORS configuration
  app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
  }));

  // Sanitize data to prevent NoSQL injection
  app.use(mongoSanitize());

  // Compress responses
  app.use(compression());

  // Request logging
  app.use(morgan('combined', {
    stream: {
      write: (message: string) => logger.info(message.trim())
    }
  }));

  // Configure passport
  configurePassport();
  app.use(passport.initialize());

  // API rate limiting
  app.use('/api', apiLimiter);

  // Routes
  app.use('/api/auth', authRoutes);

  // 404 handler
  app.use((req: Request, res: Response) => {
    res.status(404).json({ message: 'Route not found' });
  });

  // Error handler
  app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    logger.error(`Unhandled error: ${err.message}`);
    logger.error(err.stack || '');
    
    res.status(500).json({
      message: 'Internal Server Error',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  });

  return app;
};