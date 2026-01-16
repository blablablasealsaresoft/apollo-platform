import { Request, Response } from 'express';
import { listOperations, createOperation } from '../services/operation.service';

export function getOperations(_req: Request, res: Response) {
  res.json(listOperations());
}

export function postOperation(req: Request, res: Response) {
  const created = createOperation(req.body);
  res.status(201).json(created);
}
