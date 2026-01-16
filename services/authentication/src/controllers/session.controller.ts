import { Request, Response } from 'express';
import { createSession } from '../services/session.service';

export async function startSession(req: Request, res: Response) {
  const { userId } = req.body;
  const session = await createSession(userId);
  res.status(201).json(session);
}
