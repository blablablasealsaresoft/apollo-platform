import { Request, Response } from 'express';
import { uploadFile, getFileMetadata } from '../services/encryption.service';

export async function handleUpload(req: Request, res: Response) {
  const { buffer } = req.body;
  const meta = await uploadFile(buffer);
  res.status(201).json(meta);
}

export async function handleMetadata(req: Request, res: Response) {
  const meta = await getFileMetadata(req.params.id);
  res.json(meta);
}
