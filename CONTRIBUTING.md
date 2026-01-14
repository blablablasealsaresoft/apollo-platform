# Contributing to Apollo Platform

Thank you for your interest in contributing to Apollo Platform! This document provides guidelines and instructions for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contribution Guidelines](#contribution-guidelines)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Security Guidelines](#security-guidelines)

## Code of Conduct

Apollo Platform is committed to providing a welcoming and inclusive environment. All contributors are expected to:

- Be respectful and professional
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

1. **Fork the Repository**
   ```bash
   git clone https://github.com/your-username/apollo.git
   cd apollo
   ```

2. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Set Up Development Environment**
   ```bash
   npm install
   cp .env.example .env
   npm run setup:dev
   ```

## Development Setup

### Prerequisites

- Node.js >= 18.0.0
- Python >= 3.10
- Docker >= 20.10
- Kubernetes (for infrastructure development)
- PostgreSQL >= 15
- Redis >= 7

### Local Development

```bash
# Start development environment
docker-compose -f docker-compose.dev.yml up

# Run tests
npm test

# Run linter
npm run lint

# Run type checking
npm run type-check
```

## Contribution Guidelines

### What to Contribute

We welcome contributions in the following areas:

- **AI Models**: New analysis techniques, improved prompts, model integrations
- **Intelligence Tools**: OSINT/GEOINT/SIGINT integrations and enhancements
- **Red Team Tools**: C2 frameworks, payloads, evasion techniques
- **Bug Fixes**: Addressing issues in existing functionality
- **Documentation**: Improving guides, API docs, and examples
- **Performance**: Optimization and scalability improvements

### What NOT to Contribute

- Malicious code or exploits intended for unauthorized use
- Code that violates laws or regulations
- Plagiarized or unlicensed code
- Large binary files or datasets (use Git LFS)

## Pull Request Process

1. **Update Documentation**
   - Update README.md if adding new features
   - Add/update API documentation
   - Include inline code comments

2. **Write Tests**
   - Unit tests for new functionality
   - Integration tests for API changes
   - End-to-end tests for user-facing features

3. **Follow Commit Conventions**
   ```
   feat: Add new blockchain analysis module
   fix: Resolve memory leak in OSINT engine
   docs: Update API reference for intelligence-fusion service
   test: Add integration tests for C2 operations
   refactor: Restructure authentication service
   ```

4. **Submit Pull Request**
   - Provide clear description of changes
   - Reference related issues
   - Include screenshots for UI changes
   - Ensure all CI checks pass

5. **Code Review**
   - Address reviewer feedback promptly
   - Keep discussions professional and focused
   - Make requested changes in new commits

6. **Approval and Merge**
   - Requires approval from at least 2 core maintainers
   - All CI/CD checks must pass
   - No merge conflicts

## Coding Standards

### TypeScript/JavaScript

- Use TypeScript for all new code
- Follow ESLint configuration
- Use Prettier for formatting
- Maximum line length: 100 characters
- Use async/await over promises where possible

```typescript
// Good
async function fetchUserData(userId: string): Promise<User> {
  try {
    const response = await api.get(`/users/${userId}`);
    return response.data;
  } catch (error) {
    logger.error('Failed to fetch user', { userId, error });
    throw new UserNotFoundError(userId);
  }
}

// Bad
function fetchUserData(userId) {
  return api.get('/users/' + userId).then(response => {
    return response.data;
  });
}
```

### Python

- Follow PEP 8 style guide
- Use type hints
- Maximum line length: 88 characters (Black formatter)
- Use f-strings for string formatting

```python
# Good
def analyze_blockchain_transaction(
    transaction_id: str,
    network: str = "bitcoin"
) -> TransactionAnalysis:
    """Analyze a blockchain transaction for suspicious activity."""
    logger.info(f"Analyzing transaction: {transaction_id}")
    return TransactionAnalyzer(network).analyze(transaction_id)

# Bad
def analyze(txn_id, net='bitcoin'):
    return TransactionAnalyzer(net).analyze(txn_id)
```

### File Organization

- One component/class per file
- Group related files in directories
- Use index files for barrel exports
- Keep files under 500 lines

## Testing Guidelines

### Unit Tests

- Test individual functions and classes in isolation
- Mock external dependencies
- Aim for 80%+ code coverage
- Use descriptive test names

```typescript
describe('CryptoAnalyzer', () => {
  it('should identify suspicious wallet clustering patterns', async () => {
    const analyzer = new CryptoAnalyzer();
    const result = await analyzer.analyzeWallet('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');
    expect(result.suspicious).toBe(true);
    expect(result.confidence).toBeGreaterThan(0.8);
  });
});
```

### Integration Tests

- Test interactions between components
- Use test databases and services
- Clean up test data after each test

### End-to-End Tests

- Test complete user workflows
- Use Cypress or Playwright
- Run in CI/CD pipeline

## Security Guidelines

### Security-First Development

- Never commit secrets or credentials
- Use environment variables for configuration
- Validate and sanitize all inputs
- Use parameterized queries for databases
- Implement proper error handling (don't expose internals)

### Security Review Process

All PRs must pass security review:
- Static analysis (SAST)
- Dependency vulnerability scanning
- Code review by security team
- Penetration testing for critical features

### Reporting Security Vulnerabilities

**DO NOT** create public issues for security vulnerabilities.

Email: security@apollo-platform.com

Include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Questions?

- GitHub Discussions: https://github.com/apollo-platform/apollo/discussions
- Discord: https://discord.gg/apollo-platform
- Email: dev@apollo-platform.com

Thank you for contributing to Apollo Platform!
