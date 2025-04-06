import winston from 'winston';
import path from 'path';
import fs from 'fs';

// Create logs directory if it doesn't exist
const logDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

// Define log format
const logFormat = winston.format.printf(({ level, message, timestamp }) => {
  return `${timestamp} ${level}: ${message}`;
});

// Create logger instance
export const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    logFormat
  ),
  defaultMeta: { service: 'auth-service' },
  transports: [
    // Console transport for development
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        logFormat
      )
    }),
    // File transport for errors
    new winston.transports.File({ 
      filename: path.join(logDir, 'error.log'), 
      level: 'error' 
    }),
    // File transport for combined logs
    new winston.transports.File({ 
      filename: path.join(logDir, 'combined.log') 
    }),
    // Specific file for auth events
    new winston.transports.File({
      filename: path.join(logDir, 'auth.log'),
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.json()
      )
    })
  ],
});

/**
 * Log authentication events with additional context
 */
export const logAuthEvent = (
  eventType: 'login' | 'logout' | 'register' | 'passwordReset' | 'loginFailed' | 'suspicious',
  userId: string | null,
  details: Record<string, any> = {}
): void => {
  const logEntry = {
    eventType,
    userId,
    timestamp: new Date().toISOString(),
    ...details
  };
  
  logger.info(`Auth event: ${JSON.stringify(logEntry)}`);
  
  // For suspicious activities, also log as warnings
  if (eventType === 'suspicious') {
    logger.warn(`Suspicious activity: ${JSON.stringify(logEntry)}`);
  }
};

/**
 * Log user activity
 */
export const logUserActivity = (
  userId: string,
  action: string,
  details: Record<string, any> = {}
): void => {
  const logEntry = {
    userId,
    action,
    timestamp: new Date().toISOString(),
    ...details
  };
  
  logger.info(`User activity: ${JSON.stringify(logEntry)}`);
};