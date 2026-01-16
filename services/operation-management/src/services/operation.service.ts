import { Operation } from '../models/operation.model';

const operations: Operation[] = [];

export function listOperations(): Operation[] {
  return operations;
}

export function createOperation(payload: Operation): Operation {
  operations.push(payload);
  return payload;
}
