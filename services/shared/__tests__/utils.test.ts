/**
 * Shared Utilities Unit Tests
 * Tests for utility functions including ID generation, password hashing,
 * response formatting, pagination, validation, and string manipulation
 */

import {
  generateId,
  generateToken,
  hashPassword,
  comparePassword,
  sleep,
  createSuccessResponse,
  createErrorResponse,
  paginate,
  sanitizeInput,
  isValidEmail,
  isValidUUID,
  mask,
  formatBytes,
  chunkArray,
} from '../src/utils';

describe('generateId', () => {
  it('should generate a UUID string', () => {
    const id = generateId();

    expect(typeof id).toBe('string');
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  it('should generate unique IDs on each call', () => {
    const id1 = generateId();
    const id2 = generateId();
    const id3 = generateId();

    expect(id1).not.toBe(id2);
    expect(id2).not.toBe(id3);
    expect(id1).not.toBe(id3);
  });
});

describe('generateToken', () => {
  it('should generate a hex string with default length of 64 characters', () => {
    const token = generateToken();

    expect(typeof token).toBe('string');
    expect(token).toMatch(/^[0-9a-f]+$/);
    expect(token.length).toBe(64); // 32 bytes = 64 hex chars
  });

  it('should generate token with custom length', () => {
    const token = generateToken(16);

    expect(token.length).toBe(32); // 16 bytes = 32 hex chars
  });

  it('should generate unique tokens', () => {
    const token1 = generateToken();
    const token2 = generateToken();

    expect(token1).not.toBe(token2);
  });

  it('should generate short token', () => {
    const token = generateToken(4);

    expect(token.length).toBe(8); // 4 bytes = 8 hex chars
  });
});

describe('hashPassword', () => {
  it('should hash a password', async () => {
    const password = 'TestPassword123!';
    const hash = await hashPassword(password);

    expect(typeof hash).toBe('string');
    expect(hash).not.toBe(password);
    expect(hash.length).toBeGreaterThan(20);
  });

  it('should generate different hashes for same password', async () => {
    const password = 'SamePassword123!';
    const hash1 = await hashPassword(password);
    const hash2 = await hashPassword(password);

    expect(hash1).not.toBe(hash2);
  });

  it('should generate bcrypt-format hash', async () => {
    const hash = await hashPassword('test');

    expect(hash).toMatch(/^\$2[aby]\$\d+\$.{53}$/);
  });
});

describe('comparePassword', () => {
  it('should return true for matching password', async () => {
    const password = 'TestPassword123!';
    const hash = await hashPassword(password);
    const result = await comparePassword(password, hash);

    expect(result).toBe(true);
  });

  it('should return false for non-matching password', async () => {
    const hash = await hashPassword('CorrectPassword123!');
    const result = await comparePassword('WrongPassword123!', hash);

    expect(result).toBe(false);
  });

  it('should handle empty password', async () => {
    const hash = await hashPassword('');
    const result = await comparePassword('', hash);

    expect(result).toBe(true);
  });

  it('should handle special characters in password', async () => {
    const password = '!@#$%^&*()_+-=[]{}|;:,.<>?/~`';
    const hash = await hashPassword(password);
    const result = await comparePassword(password, hash);

    expect(result).toBe(true);
  });
});

describe('sleep', () => {
  it('should pause execution for specified milliseconds', async () => {
    const start = Date.now();
    await sleep(100);
    const elapsed = Date.now() - start;

    expect(elapsed).toBeGreaterThanOrEqual(95); // Allow small variance
    expect(elapsed).toBeLessThan(200);
  });

  it('should return a promise', () => {
    const result = sleep(10);

    expect(result instanceof Promise).toBe(true);
  });

  it('should resolve with undefined', async () => {
    const result = await sleep(10);

    expect(result).toBeUndefined();
  });
});

describe('createSuccessResponse', () => {
  it('should create success response with data', () => {
    const data = { id: '123', name: 'Test' };
    const response = createSuccessResponse(data);

    expect(response.success).toBe(true);
    expect(response.data).toEqual(data);
    expect(response.timestamp).toBeDefined();
    expect(new Date(response.timestamp).getTime()).not.toBeNaN();
  });

  it('should include requestId when provided', () => {
    const response = createSuccessResponse({ test: true }, 'req-123');

    expect(response.requestId).toBe('req-123');
  });

  it('should have undefined requestId when not provided', () => {
    const response = createSuccessResponse({ test: true });

    expect(response.requestId).toBeUndefined();
  });

  it('should work with null data', () => {
    const response = createSuccessResponse(null);

    expect(response.success).toBe(true);
    expect(response.data).toBeNull();
  });

  it('should work with array data', () => {
    const data = [1, 2, 3];
    const response = createSuccessResponse(data);

    expect(response.data).toEqual(data);
  });

  it('should work with primitive data', () => {
    const response = createSuccessResponse('string data');

    expect(response.data).toBe('string data');
  });
});

describe('createErrorResponse', () => {
  it('should create error response with code and message', () => {
    const response = createErrorResponse('ERROR_CODE', 'Error message');

    expect(response.success).toBe(false);
    expect(response.error?.code).toBe('ERROR_CODE');
    expect(response.error?.message).toBe('Error message');
    expect(response.timestamp).toBeDefined();
  });

  it('should include details when provided', () => {
    const details = { field: 'email', reason: 'invalid format' };
    const response = createErrorResponse('VALIDATION_ERROR', 'Validation failed', details);

    expect(response.error?.details).toEqual(details);
  });

  it('should include requestId when provided', () => {
    const response = createErrorResponse('ERROR', 'Message', null, 'req-456');

    expect(response.requestId).toBe('req-456');
  });

  it('should have undefined details when not provided', () => {
    const response = createErrorResponse('ERROR', 'Message');

    expect(response.error?.details).toBeUndefined();
  });
});

describe('paginate', () => {
  const items = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

  it('should return first page correctly', () => {
    const result = paginate(items, 1, 3);

    expect(result.items).toEqual([1, 2, 3]);
    expect(result.total).toBe(10);
    expect(result.page).toBe(1);
    expect(result.limit).toBe(3);
    expect(result.totalPages).toBe(4);
  });

  it('should return middle page correctly', () => {
    const result = paginate(items, 2, 3);

    expect(result.items).toEqual([4, 5, 6]);
    expect(result.page).toBe(2);
  });

  it('should return last page with partial items', () => {
    const result = paginate(items, 4, 3);

    expect(result.items).toEqual([10]);
    expect(result.totalPages).toBe(4);
  });

  it('should return empty items for page beyond total', () => {
    const result = paginate(items, 5, 3);

    expect(result.items).toEqual([]);
    expect(result.total).toBe(10);
  });

  it('should handle single page', () => {
    const result = paginate(items, 1, 20);

    expect(result.items).toEqual(items);
    expect(result.totalPages).toBe(1);
  });

  it('should handle empty array', () => {
    const result = paginate([], 1, 10);

    expect(result.items).toEqual([]);
    expect(result.total).toBe(0);
    expect(result.totalPages).toBe(0);
  });

  it('should handle limit of 1', () => {
    const result = paginate([1, 2, 3], 2, 1);

    expect(result.items).toEqual([2]);
    expect(result.totalPages).toBe(3);
  });

  it('should work with object arrays', () => {
    const objects = [{ id: 1 }, { id: 2 }, { id: 3 }];
    const result = paginate(objects, 1, 2);

    expect(result.items).toEqual([{ id: 1 }, { id: 2 }]);
  });
});

describe('sanitizeInput', () => {
  it('should trim whitespace', () => {
    expect(sanitizeInput('  test  ')).toBe('test');
  });

  it('should remove angle brackets', () => {
    expect(sanitizeInput('<script>alert("xss")</script>')).toBe('scriptalert("xss")/script');
  });

  it('should handle empty string', () => {
    expect(sanitizeInput('')).toBe('');
  });

  it('should handle string with only spaces', () => {
    expect(sanitizeInput('   ')).toBe('');
  });

  it('should preserve other special characters', () => {
    expect(sanitizeInput('test@email.com')).toBe('test@email.com');
    expect(sanitizeInput('hello & world')).toBe('hello & world');
  });

  it('should handle mixed content', () => {
    expect(sanitizeInput('  Hello <b>World</b>  ')).toBe('Hello bWorld/b');
  });
});

describe('isValidEmail', () => {
  it('should return true for valid email', () => {
    expect(isValidEmail('test@example.com')).toBe(true);
    expect(isValidEmail('user.name@domain.org')).toBe(true);
    expect(isValidEmail('user+tag@example.co.uk')).toBe(true);
  });

  it('should return false for invalid email', () => {
    expect(isValidEmail('invalid')).toBe(false);
    expect(isValidEmail('invalid@')).toBe(false);
    expect(isValidEmail('@domain.com')).toBe(false);
    expect(isValidEmail('user@')).toBe(false);
  });

  it('should return false for email with spaces', () => {
    expect(isValidEmail('user @domain.com')).toBe(false);
    expect(isValidEmail('user@ domain.com')).toBe(false);
  });

  it('should return false for empty string', () => {
    expect(isValidEmail('')).toBe(false);
  });

  it('should handle email with numbers', () => {
    expect(isValidEmail('user123@domain456.com')).toBe(true);
  });

  it('should handle email with hyphens', () => {
    expect(isValidEmail('user-name@sub-domain.com')).toBe(true);
  });

  it('should handle email with underscores', () => {
    expect(isValidEmail('user_name@domain.com')).toBe(true);
  });
});

describe('isValidUUID', () => {
  it('should return true for valid UUID v4', () => {
    expect(isValidUUID('550e8400-e29b-41d4-a716-446655440000')).toBe(true);
    expect(isValidUUID('6ba7b810-9dad-41d4-80b4-00c04fd430c8')).toBe(true);
    expect(isValidUUID('f47ac10b-58cc-4372-a567-0e02b2c3d479')).toBe(true);
  });

  it('should return true for UUID with uppercase letters', () => {
    expect(isValidUUID('550E8400-E29B-41D4-A716-446655440000')).toBe(true);
    expect(isValidUUID('F47AC10B-58CC-4372-A567-0E02B2C3D479')).toBe(true);
  });

  it('should return false for invalid UUID', () => {
    expect(isValidUUID('invalid-uuid')).toBe(false);
    expect(isValidUUID('550e8400-e29b-11d4-a716-446655440000')).toBe(false); // v1, not v4
    expect(isValidUUID('550e8400-e29b-41d4-c716-446655440000')).toBe(false); // wrong variant
    expect(isValidUUID('')).toBe(false);
  });

  it('should return false for UUID without hyphens', () => {
    expect(isValidUUID('550e8400e29b41d4a716446655440000')).toBe(false);
  });

  it('should return false for UUID with extra characters', () => {
    expect(isValidUUID('550e8400-e29b-41d4-a716-446655440000-extra')).toBe(false);
    expect(isValidUUID('{550e8400-e29b-41d4-a716-446655440000}')).toBe(false);
  });
});

describe('mask', () => {
  it('should mask string with default visible characters', () => {
    expect(mask('1234567890')).toBe('******7890');
  });

  it('should mask string with custom visible characters', () => {
    expect(mask('1234567890', 2)).toBe('********90');
    expect(mask('1234567890', 6)).toBe('****567890');
  });

  it('should return all asterisks when string length equals visible chars', () => {
    expect(mask('1234', 4)).toBe('****');
  });

  it('should return all asterisks when string length is less than visible chars', () => {
    expect(mask('123', 4)).toBe('***');
  });

  it('should handle empty string', () => {
    expect(mask('')).toBe('');
  });

  it('should handle single character', () => {
    expect(mask('A', 1)).toBe('*');
    expect(mask('A', 4)).toBe('*');
  });

  it('should mask email addresses', () => {
    expect(mask('test@example.com', 4)).toBe('************.com');
  });

  it('should mask credit card numbers', () => {
    expect(mask('4111111111111111', 4)).toBe('************1111');
  });
});

describe('formatBytes', () => {
  it('should format 0 bytes', () => {
    expect(formatBytes(0)).toBe('0 Bytes');
  });

  it('should format bytes', () => {
    expect(formatBytes(500)).toBe('500 Bytes');
    expect(formatBytes(1023)).toBe('1023 Bytes');
  });

  it('should format kilobytes', () => {
    expect(formatBytes(1024)).toBe('1 KB');
    expect(formatBytes(1536)).toBe('1.5 KB');
  });

  it('should format megabytes', () => {
    expect(formatBytes(1048576)).toBe('1 MB');
    expect(formatBytes(2621440)).toBe('2.5 MB');
  });

  it('should format gigabytes', () => {
    expect(formatBytes(1073741824)).toBe('1 GB');
    expect(formatBytes(5368709120)).toBe('5 GB');
  });

  it('should format terabytes', () => {
    expect(formatBytes(1099511627776)).toBe('1 TB');
  });

  it('should use custom decimal precision', () => {
    expect(formatBytes(1536, 0)).toBe('2 KB');
    expect(formatBytes(1536, 3)).toBe('1.5 KB');
    expect(formatBytes(1536, 1)).toBe('1.5 KB');
  });

  it('should handle large numbers', () => {
    expect(formatBytes(10995116277760)).toBe('10 TB');
  });
});

describe('chunkArray', () => {
  it('should split array into chunks of specified size', () => {
    const array = [1, 2, 3, 4, 5, 6, 7, 8];
    const chunks = chunkArray(array, 3);

    expect(chunks).toEqual([[1, 2, 3], [4, 5, 6], [7, 8]]);
  });

  it('should handle array smaller than chunk size', () => {
    const array = [1, 2];
    const chunks = chunkArray(array, 5);

    expect(chunks).toEqual([[1, 2]]);
  });

  it('should handle array equal to chunk size', () => {
    const array = [1, 2, 3];
    const chunks = chunkArray(array, 3);

    expect(chunks).toEqual([[1, 2, 3]]);
  });

  it('should handle empty array', () => {
    const chunks = chunkArray([], 3);

    expect(chunks).toEqual([]);
  });

  it('should handle chunk size of 1', () => {
    const array = [1, 2, 3];
    const chunks = chunkArray(array, 1);

    expect(chunks).toEqual([[1], [2], [3]]);
  });

  it('should work with objects', () => {
    const array = [{ id: 1 }, { id: 2 }, { id: 3 }];
    const chunks = chunkArray(array, 2);

    expect(chunks).toEqual([[{ id: 1 }, { id: 2 }], [{ id: 3 }]]);
  });

  it('should work with strings', () => {
    const array = ['a', 'b', 'c', 'd', 'e'];
    const chunks = chunkArray(array, 2);

    expect(chunks).toEqual([['a', 'b'], ['c', 'd'], ['e']]);
  });

  it('should preserve original array', () => {
    const array = [1, 2, 3, 4, 5];
    chunkArray(array, 2);

    expect(array).toEqual([1, 2, 3, 4, 5]);
  });
});
