declare namespace Express {
    export interface Request {
      userId: string;
      user?: import('./db').DbUser;
    }
  }