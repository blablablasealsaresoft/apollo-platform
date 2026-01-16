/**
 * API Orchestrator Tests
 *
 * @elite-engineering
 */

import { APIOrchestrator } from '../apollo-integration/api-orchestrator';

describe('APIOrchestrator', () => {
  let orchestrator: APIOrchestrator;

  beforeEach(() => {
    orchestrator = new APIOrchestrator();
  });

  describe('API Selection', () => {
    test('should select relevant APIs for crypto investigation', async () => {
      const apis = await orchestrator.selectAPIsForTask({
        objective: 'Track OneCoin cryptocurrency activity',
        categories: ['cryptocurrency'],
        priority: 'critical'
      });

      expect(apis).toContain('coingecko');
      expect(apis).toContain('blockchain_info');
      expect(apis.length).toBeGreaterThan(3);
    });

    test('should select geolocation APIs for IP tracking', async () => {
      const apis = await orchestrator.selectAPIsForTask({
        objective: 'Track IP addresses',
        categories: ['geolocation'],
        priority: 'high'
      });

      expect(apis).toContain('ipstack');
      expect(apis).toContain('ipapi');
    });
  });

  describe('Autonomous Investigation', () => {
    test('should complete autonomous investigation', async () => {
      const report = await orchestrator.autonomousInvestigation(
        'Test investigation objective'
      );

      expect(report).toHaveProperty('objective');
      expect(report).toHaveProperty('apisUsed');
      expect(report).toHaveProperty('intelligence');
      expect(report.apisUsed).toBeGreaterThan(0);
    });

    test('should generate intelligence report', async () => {
      const report = await orchestrator.autonomousInvestigation(
        'Find crypto activity',
        { priority: 'high' }
      );

      expect(report.intelligence).toHaveProperty('findings');
      expect(report.intelligence).toHaveProperty('correlations');
      expect(report.intelligence).toHaveProperty('alerts');
      expect(report.intelligence).toHaveProperty('confidence');
    });
  });

  describe('Continuous Monitoring', () => {
    test('should deploy continuous monitoring', async () => {
      await expect(
        orchestrator.deployContinuousMonitoring('test_mission', {
          frequency: 60,
          alertThreshold: 0.8
        })
      ).resolves.not.toThrow();
    });
  });
});
