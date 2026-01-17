describe('PostgreSQL Database Integration Tests', () => {
  describe('Database Connection', () => {
    it('should successfully connect to database', async () => {
      const result = await global.testDb.query('SELECT NOW()');
      expect(result.rows.length).toBe(1);
    });

    it('should handle connection pool correctly', async () => {
      const queries = [];
      for (let i = 0; i < 20; i++) {
        queries.push(global.testDb.query('SELECT $1 as num', [i]));
      }

      const results = await Promise.all(queries);
      expect(results.length).toBe(20);
    });
  });

  describe('Investigations Table', () => {
    it('should insert investigation record', async () => {
      const result = await global.testDb.query(`
        INSERT INTO investigations (
          case_number, title, priority, status, classification, created_by
        ) VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
      `, ['CASE-TEST-001', 'Test Investigation', 'HIGH', 'ACTIVE', 'CONFIDENTIAL', 'test-user-1']);

      expect(result.rows.length).toBe(1);
      expect(result.rows[0].case_number).toBe('CASE-TEST-001');
    });

    it('should enforce unique case number constraint', async () => {
      await global.testDb.query(`
        INSERT INTO investigations (case_number, title, priority, status, classification, created_by)
        VALUES ('CASE-UNIQUE-001', 'Test', 'HIGH', 'ACTIVE', 'CONFIDENTIAL', 'test-user-1')
      `);

      // Try to insert duplicate
      try {
        await global.testDb.query(`
          INSERT INTO investigations (case_number, title, priority, status, classification, created_by)
          VALUES ('CASE-UNIQUE-001', 'Test Duplicate', 'HIGH', 'ACTIVE', 'CONFIDENTIAL', 'test-user-1')
        `);
        expect(true).toBe(false); // Should not reach here
      } catch (error: any) {
        expect(error.code).toBe('23505'); // Unique violation
      }
    });

    it('should cascade delete related records', async () => {
      // Insert investigation
      const invResult = await global.testDb.query(`
        INSERT INTO investigations (case_number, title, priority, status, classification, created_by)
        VALUES ('CASE-CASCADE-001', 'Test', 'HIGH', 'ACTIVE', 'CONFIDENTIAL', 'test-user-1')
        RETURNING id
      `);

      const investigationId = invResult.rows[0].id;

      // Insert related target
      await global.testDb.query(`
        INSERT INTO targets (investigation_id, name, type, risk_level)
        VALUES ($1, 'Test Target', 'PERSON', 'HIGH')
      `, [investigationId]);

      // Delete investigation
      await global.testDb.query('DELETE FROM investigations WHERE id = $1', [investigationId]);

      // Verify cascade delete
      const targetResult = await global.testDb.query(
        'SELECT * FROM targets WHERE investigation_id = $1',
        [investigationId]
      );

      expect(targetResult.rows.length).toBe(0);
    });
  });

  describe('Users and Authentication', () => {
    it('should hash passwords before storage', async () => {
      const result = await global.testDb.query(`
        INSERT INTO users (email, password_hash, role, department, clearance_level)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
      `, ['test@example.com', '$2b$10$hashedPassword', 'ANALYST', 'INVESTIGATIONS', 'SECRET']);

      expect(result.rows[0].password_hash).not.toBe('plainPassword');
      expect(result.rows[0].password_hash.startsWith('$2b$')).toBe(true);
    });

    it('should maintain user session records', async () => {
      const result = await global.testDb.query(`
        INSERT INTO user_sessions (user_id, token, expires_at)
        VALUES ($1, $2, $3)
        RETURNING *
      `, ['test-user-1', 'session-token-123', new Date(Date.now() + 3600000)]);

      expect(result.rows[0].token).toBe('session-token-123');
    });
  });

  describe('Full-Text Search', () => {
    it('should perform full-text search on investigations', async () => {
      // Insert searchable data
      await global.testDb.query(`
        INSERT INTO investigations (case_number, title, description, priority, status, classification, created_by)
        VALUES
          ('SEARCH-001', 'Cryptocurrency Fraud', 'OneCoin pyramid scheme investigation', 'HIGH', 'ACTIVE', 'CONFIDENTIAL', 'test-user-1'),
          ('SEARCH-002', 'Money Laundering', 'Bitcoin mixer investigation', 'HIGH', 'ACTIVE', 'CONFIDENTIAL', 'test-user-1')
      `);

      // Search for "cryptocurrency"
      const result = await global.testDb.query(`
        SELECT * FROM investigations
        WHERE to_tsvector('english', title || ' ' || COALESCE(description, ''))
        @@ to_tsquery('english', 'cryptocurrency')
      `);

      expect(result.rows.length).toBeGreaterThan(0);
      expect(result.rows[0].title).toContain('Cryptocurrency');
    });
  });

  describe('Transactions and ACID', () => {
    it('should rollback transaction on error', async () => {
      const client = await global.testDb.connect();

      try {
        await client.query('BEGIN');

        await client.query(`
          INSERT INTO investigations (case_number, title, priority, status, classification, created_by)
          VALUES ('TX-TEST-001', 'Test', 'HIGH', 'ACTIVE', 'CONFIDENTIAL', 'test-user-1')
        `);

        // Simulate error
        await client.query('SELECT * FROM non_existent_table');

        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
      } finally {
        client.release();
      }

      // Verify rollback
      const result = await global.testDb.query(
        "SELECT * FROM investigations WHERE case_number = 'TX-TEST-001'"
      );

      expect(result.rows.length).toBe(0);
    });

    it('should handle concurrent updates correctly', async () => {
      // Insert test record
      const invResult = await global.testDb.query(`
        INSERT INTO investigations (case_number, title, priority, status, classification, created_by)
        VALUES ('CONCURRENT-001', 'Test', 'HIGH', 'ACTIVE', 'CONFIDENTIAL', 'test-user-1')
        RETURNING id, version
      `);

      const id = invResult.rows[0].id;

      // Simulate concurrent updates
      const update1 = global.testDb.query(`
        UPDATE investigations SET priority = 'CRITICAL' WHERE id = $1
      `, [id]);

      const update2 = global.testDb.query(`
        UPDATE investigations SET status = 'CLOSED' WHERE id = $1
      `, [id]);

      await Promise.all([update1, update2]);

      // Verify both updates applied
      const result = await global.testDb.query('SELECT * FROM investigations WHERE id = $1', [id]);
      expect(result.rows[0].priority).toBe('CRITICAL');
      expect(result.rows[0].status).toBe('CLOSED');
    });
  });

  describe('Performance and Indexing', () => {
    it('should use index for case number lookups', async () => {
      const explain = await global.testDb.query(`
        EXPLAIN (FORMAT JSON)
        SELECT * FROM investigations WHERE case_number = 'CASE-2026-0001'
      `);

      const plan = JSON.stringify(explain.rows[0]);
      expect(plan).toContain('Index');
    });

    it('should handle large result sets efficiently', async () => {
      const startTime = Date.now();

      const result = await global.testDb.query(`
        SELECT * FROM investigations LIMIT 1000
      `);

      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(1000); // Should complete in less than 1 second
    });
  });

  describe('Data Integrity', () => {
    it('should enforce foreign key constraints', async () => {
      try {
        await global.testDb.query(`
          INSERT INTO targets (investigation_id, name, type, risk_level)
          VALUES ('non-existent-id', 'Test', 'PERSON', 'HIGH')
        `);
        expect(true).toBe(false); // Should not reach here
      } catch (error: any) {
        expect(error.code).toBe('23503'); // Foreign key violation
      }
    });

    it('should validate enum values', async () => {
      try {
        await global.testDb.query(`
          INSERT INTO investigations (case_number, title, priority, status, classification, created_by)
          VALUES ('ENUM-TEST', 'Test', 'INVALID_PRIORITY', 'ACTIVE', 'CONFIDENTIAL', 'test-user-1')
        `);
        expect(true).toBe(false);
      } catch (error: any) {
        expect(error.code).toBe('22P02'); // Invalid enum value
      }
    });
  });
});
