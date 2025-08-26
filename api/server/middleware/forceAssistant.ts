import type { Request, Response, NextFunction } from 'express';
import { getDb } from '../db'; // adjust to your project
import { ObjectId } from 'mongodb';

export async function forceAssistant(req: Request, res: Response, next: NextFunction) {
  try {
    // adjust to however you store auth; common: req.user.id or req.session.userId
    const userId = (req as any).user?._id || (req as any).user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const db = await getDb();
    const user = await db.collection('users').findOne(
      { _id: new ObjectId(String(userId)) },
      { projection: { personalization: 1 } }
    );

    const asst = user?.personalization?.openaiAssistantId;
    if (!asst) return res.status(403).json({ error: 'No assistant bound to this user' });

    (req as any).assistantId = asst;
    next();
  } catch (e) {
    next(e);
  }
}
