import { Request, Response, NextFunction } from 'express';

export function auditTrail(req: Request, _res: Response, next: NextFunction) {
  console.log(`[file-storage] ${req.method} ${req.path}`);
  next();
}
