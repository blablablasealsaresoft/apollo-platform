import { createOperation, listOperations } from '../src/services/operation.service';

test('createOperation stores operation', () => {
  const op = createOperation({ id: '1', title: 'Test', status: 'planning', priority: 'medium' });
  expect(listOperations()).toContain(op);
});
