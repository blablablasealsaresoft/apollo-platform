import { Operation } from '../models/operation.model';

export function nextStatus(operation: Operation): Operation['status'] {
  switch (operation.status) {
    case 'planning':
      return 'active';
    case 'active':
      return 'complete';
    default:
      return 'complete';
  }
}
