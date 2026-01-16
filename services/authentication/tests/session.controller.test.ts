import { startSession } from '../src/controllers/session.controller';

test('startSession returns 201', async () => {
  const req: any = { body: { userId: 'test-user' } };
  const res: any = {
    statusCode: 0,
    payload: null,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(body: any) {
      this.payload = body;
    },
  };

  await startSession(req, res);

  expect(res.statusCode).toBe(201);
  expect(res.payload.userId).toBe('test-user');
});
