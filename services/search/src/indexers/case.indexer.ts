import { normalizeQuery } from '../analyzers/query.analyzer';

export function indexCase(caseNumber: string): string {
  return `case://${normalizeQuery(caseNumber)}`;
}
