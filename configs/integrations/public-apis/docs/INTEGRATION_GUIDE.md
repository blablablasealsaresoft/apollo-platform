# Apollo Platform - Public APIs Integration Guide

## Quick Start

### 1. Installation

```bash
cd configs/integrations/public-apis
npm install
npm run build
```

### 2. Configuration

Create `.env` file:

```env
# Critical APIs (optional - increases rate limits)
IPSTACK_API_KEY=your_key
ETHERSCAN_API_KEY=your_key
ALPHA_VANTAGE_API_KEY=your_key
```

### 3. Deploy

```bash
# Deploy Ignatova hunt
npm run deploy-ignatova

# Or run autonomous demo
npm run autonomous-demo
```

---

## Usage Patterns

### Pattern 1: Simple Investigation

```typescript
import { apiOrchestrator } from '@apollo/public-apis-integration';

const report = await apiOrchestrator.autonomousInvestigation(
  "Your objective here"
);
```

### Pattern 2: Mission-Specific

```typescript
const report = await apiOrchestrator.autonomousInvestigation(
  "Your objective",
  {
    mission: 'ignatova_hunt',
    priority: 'critical',
    categories: ['cryptocurrency', 'geolocation']
  }
);
```

### Pattern 3: Continuous Monitoring

```typescript
await apiOrchestrator.deployContinuousMonitoring('mission_name', {
  frequency: 60,
  alertThreshold: 0.8,
  autoResponse: true
});
```

---

## Adding New APIs

### Step 1: Add to Registry

Edit `api-registry.json`:

```json
{
  "id": "new_api",
  "name": "New API",
  "url": "https://api.example.com",
  "auth": "apiKey",
  "free": true,
  "rate_limit": "1000/day",
  "description": "API description",
  "apollo_use": "How Apollo uses it",
  "priority": "high"
}
```

### Step 2: Add to Category

Edit appropriate category YAML file:

```yaml
new_api:
  name: New API
  url: https://api.example.com
  authentication: apiKey
  free_tier: true

  apollo_integration:
    use_case: "Integration use case"
    priority: high
```

### Step 3: Test

```typescript
import { apiCaller } from './apollo-integration/api-caller';

const result = await apiCaller.call(newAPI, {
  endpoint: '/test',
  params: { key: 'value' }
});
```

---

## Best Practices

1. **Always use AI orchestrator** - Let AI select APIs
2. **Set appropriate priority** - Critical for time-sensitive ops
3. **Use categories** - Filter APIs by category
4. **Enable continuous monitoring** - For ongoing missions
5. **Configure alerts** - Don't miss critical findings
6. **Validate results** - Use multi-source validation

---

## Troubleshooting

### Rate Limits

- Use API keys for higher limits
- Implement exponential backoff
- Use multiple APIs for redundancy

### Errors

- Check error handler logs
- Verify API keys in .env
- Check network connectivity
- Review API documentation

---

## Performance Optimization

1. **Parallel execution** - Default enabled
2. **Caching** - Coming soon
3. **Rate limit optimization** - Auto-managed
4. **Failover** - Auto-enabled

---

**For more examples, see `examples/` directory.**
