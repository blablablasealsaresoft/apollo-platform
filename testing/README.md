# Apollo Platform - Testing Suite

Comprehensive testing infrastructure for the Apollo Platform, ensuring code quality, security, and reliability.

## Table of Contents
- [Overview](#overview)
- [Test Coverage Requirements](#test-coverage-requirements)
- [Running Tests](#running-tests)
- [Test Structure](#test-structure)
- [CI/CD Integration](#cicd-integration)
- [Writing Tests](#writing-tests)
- [Test Data](#test-data)
- [Performance Benchmarks](#performance-benchmarks)

---

## Overview

The Apollo Platform testing suite includes:
- **Unit Tests**: 80%+ code coverage requirement
- **Integration Tests**: API, database, and service-to-service testing
- **E2E Tests**: Complete user journey testing with Cypress and Playwright
- **Load Tests**: Performance testing with k6 (1000+ concurrent users)
- **Security Tests**: OWASP ZAP, vulnerability scanning, penetration testing

### Test Coverage Requirements

All services must maintain minimum test coverage:
- **Lines**: 80%
- **Branches**: 80%
- **Functions**: 80%
- **Statements**: 80%

---

## Running Tests

### Unit Tests

#### Run all unit tests:
```bash
npm run test:unit
```

#### Run with coverage:
```bash
npm run test:unit -- --coverage
```

#### Run specific test file:
```bash
npm run test:unit -- path/to/test.test.ts
```

#### Run tests in watch mode:
```bash
npm run test:unit -- --watch
```

#### Run Python unit tests:
```bash
pytest testing/unit-tests/intelligence --cov --cov-report=html
```

### Integration Tests

#### Prerequisites:
- Docker and Docker Compose installed
- Database services running (PostgreSQL, Redis, Elasticsearch, RabbitMQ)

#### Start test infrastructure:
```bash
docker-compose -f docker-compose.test.yml up -d
```

#### Run integration tests:
```bash
npm run test:integration
```

#### Run specific integration test suite:
```bash
npm run test:integration -- --testPathPattern=database
```

#### Stop test infrastructure:
```bash
docker-compose -f docker-compose.test.yml down
```

### E2E Tests

#### Using Cypress:
```bash
# Open Cypress Test Runner (interactive)
npm run test:e2e:open

# Run Cypress tests (headless)
npm run test:e2e
```

#### Using Playwright:
```bash
# Install browsers
npx playwright install

# Run Playwright tests
npm run test:playwright

# Run with UI
npm run test:playwright -- --ui

# Run specific browser
npm run test:playwright -- --project=chromium
```

### Load Tests

#### Prerequisites:
- k6 installed ([installation guide](https://k6.io/docs/getting-started/installation/))

#### Run load test:
```bash
k6 run testing/performance-tests/load-tests/investigation-api-load.js
```

#### Run with custom parameters:
```bash
k6 run --vus 100 --duration 5m testing/performance-tests/load-tests/investigation-api-load.js
```

#### Generate HTML report:
```bash
k6 run --out json=results.json testing/performance-tests/load-tests/investigation-api-load.js
```

### Security Tests

#### Run all security tests:
```bash
npm run test:security
```

#### Run OWASP ZAP scan:
```bash
bash testing/security-tests/vulnerability-scanner.sh
```

#### Run dependency audit:
```bash
npm audit
npm run security:dependencies
```

#### Run Snyk security scan:
```bash
snyk test
```

#### Run Semgrep SAST:
```bash
semgrep --config=auto .
```

---

## Test Structure

```
testing/
├── unit-tests/              # Unit tests for all services
│   ├── services/           # Backend service tests
│   ├── frontend/           # Frontend component tests
│   ├── intelligence/       # Intelligence service tests
│   ├── ai-engine/          # AI/ML tests
│   └── utils/              # Utility function tests
│
├── integration-tests/      # Integration tests
│   ├── api-tests/         # API endpoint tests
│   ├── database-tests/    # Database integration tests
│   ├── ai-integration/    # AI service integration tests
│   └── workflow-tests/    # Business workflow tests
│
├── e2e-tests/             # End-to-end tests
│   ├── user-journeys/     # Complete user flows
│   ├── investigation-workflows/  # Investigation scenarios
│   ├── intelligence-collection/  # Intelligence gathering flows
│   └── operation-execution/      # Operation workflows
│
├── performance-tests/     # Performance and load tests
│   └── load-tests/       # k6 load testing scripts
│
├── security-tests/       # Security testing
│   ├── owasp-zap-config.yaml
│   ├── vulnerability-scanner.sh
│   └── reports/          # Security scan reports
│
├── test-data/            # Test data and fixtures
│   ├── generators/       # Test data generators
│   ├── fixtures/         # Static test data
│   └── mocks/           # Mock responses
│
└── test-utilities/       # Test utilities and helpers
    ├── jest.setup.js
    ├── integration.setup.js
    └── frontend.setup.js
```

---

## CI/CD Integration

### GitHub Actions Workflows

#### Main CI Pipeline (`.github/workflows/ci-main.yml`)
Triggered on push to agent branches:
- Linting (ESLint, Pylint, Prettier)
- Type checking
- Unit tests with coverage
- Integration tests
- Security scanning
- Docker image builds

#### Pre-Merge Pipeline (`.github/workflows/ci-merge.yml`)
Triggered on PR to master:
- Full test suite
- E2E tests
- Load tests
- Security audit
- Code quality gate
- Manual approval requirement

#### Deployment Pipeline (`.github/workflows/cd-deploy.yml`)
Triggered on push to master:
- Build production images
- Deploy to staging
- Smoke tests
- Manual approval for production
- Production deployment
- Health checks
- Rollback on failure

---

## Writing Tests

### Unit Test Example (TypeScript)

```typescript
import { describe, it, expect, jest } from '@jest/globals';

describe('InvestigationService', () => {
  describe('createInvestigation', () => {
    it('should create investigation with valid data', async () => {
      const data = {
        caseNumber: 'CASE-2026-0001',
        title: 'Test Investigation',
        priority: 'HIGH',
        classification: 'CONFIDENTIAL',
      };

      const result = await investigationService.create(data);

      expect(result).toHaveProperty('id');
      expect(result.caseNumber).toBe(data.caseNumber);
      expect(result.status).toBe('ACTIVE');
    });

    it('should validate required fields', async () => {
      const invalidData = { title: 'Test' };

      await expect(
        investigationService.create(invalidData)
      ).rejects.toThrow('Missing required fields');
    });
  });
});
```

### Integration Test Example (TypeScript)

```typescript
import { describe, it, expect } from '@jest/globals';
import request from 'supertest';

describe('Investigation API Integration', () => {
  let authToken: string;

  beforeAll(async () => {
    // Login and get token
    const response = await request(API_URL)
      .post('/auth/login')
      .send({ email: 'test@example.com', password: 'password' });
    authToken = response.body.token;
  });

  it('should create and retrieve investigation', async () => {
    // Create
    const createResponse = await request(API_URL)
      .post('/investigations')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        caseNumber: 'TEST-001',
        title: 'Test Case',
        priority: 'HIGH',
        classification: 'CONFIDENTIAL',
      })
      .expect(201);

    const investigationId = createResponse.body.id;

    // Retrieve
    const getResponse = await request(API_URL)
      .get(`/investigations/${investigationId}`)
      .set('Authorization', `Bearer ${authToken}`)
      .expect(200);

    expect(getResponse.body.id).toBe(investigationId);
  });
});
```

### E2E Test Example (Cypress)

```typescript
describe('Investigation Workflow', () => {
  beforeEach(() => {
    cy.visit('/login');
    cy.login('analyst@test.com', 'password');
  });

  it('should complete full investigation workflow', () => {
    // Create investigation
    cy.get('[data-testid="create-investigation"]').click();
    cy.get('[data-testid="case-number"]').type('E2E-TEST-001');
    cy.get('[data-testid="title"]').type('E2E Test Investigation');
    cy.get('[data-testid="priority"]').select('CRITICAL');
    cy.get('[data-testid="save"]').click();

    // Verify creation
    cy.get('[data-testid="success-notification"]').should('be.visible');
    cy.url().should('include', '/investigations/');

    // Add target
    cy.get('[data-testid="add-target"]').click();
    cy.get('[data-testid="target-name"]').type('Test Target');
    cy.get('[data-testid="save-target"]').click();

    // Verify target added
    cy.get('[data-testid="target-list"]').should('contain', 'Test Target');
  });
});
```

---

## Test Data

### Generating Test Data

```typescript
import { generateTestDataset } from './test-data/generators/test-data-generator';

// Generate complete test dataset
const dataset = generateTestDataset();

// Generate specific entities
const user = generateUser({ role: 'ADMIN' });
const investigation = generateInvestigation({ priority: 'CRITICAL' });
const target = generateTarget({ type: 'PERSON' });
```

### Mock Data

Mock API responses are available in `testing/test-data/mocks/`.

### Fixtures

Static test data (images, documents, etc.) in `testing/test-data/fixtures/`.

---

## Performance Benchmarks

### Target Metrics

#### API Response Times:
- p50: < 100ms
- p95: < 300ms
- p99: < 500ms

#### Database Queries:
- Simple queries: < 50ms
- Complex queries: < 200ms
- Full-text search: < 300ms

#### AI/ML Operations:
- Facial recognition: < 500ms per frame
- Blockchain analysis: < 2s per address
- Intelligence fusion: < 1s per query

#### Real-time Features:
- WebSocket latency: < 100ms
- Alert delivery: < 1s end-to-end
- Notification delivery: < 2s

### Load Testing Thresholds:
- Concurrent users: 1,000+
- Requests per second: 10,000+
- Error rate: < 1%
- CPU usage: < 70%
- Memory usage: < 80%

---

## Best Practices

### 1. Test Naming
```typescript
// Good
describe('AuthenticationService', () => {
  it('should reject invalid credentials', async () => {});
  it('should generate JWT token on successful login', async () => {});
});

// Avoid
describe('Auth', () => {
  it('test1', () => {});
});
```

### 2. Arrange-Act-Assert Pattern
```typescript
it('should calculate total correctly', () => {
  // Arrange
  const items = [{ price: 10 }, { price: 20 }];

  // Act
  const total = calculateTotal(items);

  // Assert
  expect(total).toBe(30);
});
```

### 3. Mock External Dependencies
```typescript
jest.mock('axios');
jest.mock('openai');

it('should handle API failure', async () => {
  axios.get.mockRejectedValue(new Error('API Error'));

  await expect(fetchData()).rejects.toThrow('API Error');
});
```

### 4. Clean Up After Tests
```typescript
afterEach(() => {
  jest.clearAllMocks();
});

afterAll(async () => {
  await cleanupDatabase();
  await closeConnections();
});
```

### 5. Test Edge Cases
```typescript
it('should handle empty input', () => {});
it('should handle null values', () => {});
it('should handle maximum values', () => {});
it('should handle concurrent requests', () => {});
```

---

## Troubleshooting

### Tests Failing Locally

1. **Database connection issues:**
   ```bash
   docker-compose -f docker-compose.test.yml up -d
   ```

2. **Port conflicts:**
   ```bash
   lsof -i :5432  # Check what's using the port
   ```

3. **Clear test cache:**
   ```bash
   npm run test:unit -- --clearCache
   ```

### Tests Passing Locally But Failing in CI

1. **Check environment variables**
2. **Verify Node.js/Python versions match**
3. **Check for timing issues (increase timeouts)**
4. **Review CI logs for specific errors**

### Slow Tests

1. **Run tests in parallel:**
   ```bash
   npm run test:unit -- --maxWorkers=4
   ```

2. **Identify slow tests:**
   ```bash
   npm run test:unit -- --verbose
   ```

3. **Mock external APIs**
4. **Use test database with smaller dataset**

---

## Resources

- [Jest Documentation](https://jestjs.io/docs/getting-started)
- [Pytest Documentation](https://docs.pytest.org/)
- [Cypress Documentation](https://docs.cypress.io/)
- [Playwright Documentation](https://playwright.dev/)
- [k6 Documentation](https://k6.io/docs/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

## Support

For testing support:
- Slack: #apollo-testing
- Email: qa@apollo-platform.com
- Wiki: [Testing Guidelines](https://wiki.apollo-platform.com/testing)
