import type { Request, Response } from 'express';
import { app } from '../app.ts';

/**
 * Vercel Serverless Function entry point.
 * Forwards all /api/* requests to the Express application.
 */
export default function handler(req: Request, res: Response) {
  return app(req, res);
}

export { app };
