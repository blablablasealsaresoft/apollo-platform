describe('Investigation Workflow E2E Test', () => {
  beforeEach(() => {
    // Clear database and seed test data
    cy.task('clearDatabase');
    cy.task('seedDatabase');

    // Visit login page
    cy.visit('/login');
  });

  it('should complete full investigation workflow', () => {
    // Step 1: Login
    cy.get('[data-testid="email-input"]').type(Cypress.env('testUser').email);
    cy.get('[data-testid="password-input"]').type(Cypress.env('testUser').password);
    cy.get('[data-testid="login-button"]').click();

    // Verify successful login
    cy.url().should('include', '/dashboard');
    cy.get('[data-testid="user-menu"]').should('be.visible');

    // Step 2: Create New Investigation
    cy.get('[data-testid="create-investigation-button"]').click();

    cy.get('[data-testid="case-number-input"]').type('CASE-2026-E2E-001');
    cy.get('[data-testid="title-input"]').type('OneCoin Investigation - Ruja Ignatova');
    cy.get('[data-testid="description-input"]').type('Tracking the CryptoQueen and OneCoin fraud');

    cy.get('[data-testid="priority-select"]').select('CRITICAL');
    cy.get('[data-testid="classification-select"]').select('TOP_SECRET');

    cy.get('[data-testid="save-investigation-button"]').click();

    // Verify investigation created
    cy.get('[data-testid="success-notification"]').should('contain', 'Investigation created');
    cy.url().should('match', /\/investigations\/[a-zA-Z0-9-]+$/);

    // Step 3: Add Target to Investigation
    cy.get('[data-testid="add-target-button"]').click();

    cy.get('[data-testid="target-name-input"]').type('Ruja Ignatova');
    cy.get('[data-testid="target-type-select"]').select('PERSON');
    cy.get('[data-testid="risk-level-select"]').select('CRITICAL');

    cy.get('[data-testid="alias-input"]').type('CryptoQueen');
    cy.get('[data-testid="add-alias-button"]').click();

    cy.get('[data-testid="dob-input"]').type('1980-05-30');
    cy.get('[data-testid="nationality-input"]').type('Bulgarian');

    cy.get('[data-testid="save-target-button"]').click();

    // Verify target added
    cy.get('[data-testid="target-list"]').should('contain', 'Ruja Ignatova');
    cy.get('[data-testid="target-list"]').should('contain', 'CryptoQueen');

    // Step 4: Upload Evidence
    cy.get('[data-testid="evidence-tab"]').click();
    cy.get('[data-testid="upload-evidence-button"]').click();

    const fileName = 'bank-statement.pdf';
    cy.get('[data-testid="file-input"]').selectFile({
      contents: Cypress.Buffer.from('fake pdf content'),
      fileName: fileName,
      mimeType: 'application/pdf',
    });

    cy.get('[data-testid="evidence-description"]').type('Suspicious bank transfers to OneCoin accounts');
    cy.get('[data-testid="evidence-type-select"]').select('FINANCIAL_DOCUMENT');

    cy.get('[data-testid="upload-button"]').click();

    // Verify evidence uploaded
    cy.get('[data-testid="evidence-list"]').should('contain', fileName);

    // Step 5: Search Evidence
    cy.get('[data-testid="search-tab"]').click();
    cy.get('[data-testid="search-input"]').type('bank transfers');
    cy.get('[data-testid="search-button"]').click();

    // Verify search results
    cy.get('[data-testid="search-results"]').should('contain', fileName);

    // Step 6: View Investigation Dashboard
    cy.get('[data-testid="dashboard-tab"]').click();

    // Verify dashboard elements
    cy.get('[data-testid="investigation-status"]').should('contain', 'ACTIVE');
    cy.get('[data-testid="target-count"]').should('contain', '1');
    cy.get('[data-testid="evidence-count"]').should('contain', '1');
    cy.get('[data-testid="priority-badge"]').should('contain', 'CRITICAL');

    // Step 7: View Timeline
    cy.get('[data-testid="timeline-tab"]').click();

    cy.get('[data-testid="timeline-events"]')
      .should('contain', 'Investigation created')
      .and('contain', 'Target added')
      .and('contain', 'Evidence uploaded');

    // Step 8: Generate Report
    cy.get('[data-testid="reports-tab"]').click();
    cy.get('[data-testid="generate-report-button"]').click();

    cy.get('[data-testid="report-type-select"]').select('COMPREHENSIVE');
    cy.get('[data-testid="include-evidence-checkbox"]').check();
    cy.get('[data-testid="include-timeline-checkbox"]').check();

    cy.get('[data-testid="generate-button"]').click();

    // Verify report generation
    cy.get('[data-testid="success-notification"]').should('contain', 'Report generated');

    // Step 9: Update Investigation Status
    cy.get('[data-testid="update-status-button"]').click();
    cy.get('[data-testid="status-select"]').select('UNDER_REVIEW');
    cy.get('[data-testid="status-notes"]').type('Case under supervisory review');
    cy.get('[data-testid="confirm-status-button"]').click();

    // Verify status updated
    cy.get('[data-testid="investigation-status"]').should('contain', 'UNDER_REVIEW');

    // Step 10: Logout
    cy.get('[data-testid="user-menu"]').click();
    cy.get('[data-testid="logout-button"]').click();

    // Verify logout
    cy.url().should('include', '/login');
  });

  it('should handle real-time alerts', () => {
    // Login
    cy.get('[data-testid="email-input"]').type(Cypress.env('testUser').email);
    cy.get('[data-testid="password-input"]').type(Cypress.env('testUser').password);
    cy.get('[data-testid="login-button"]').click();

    // Enable real-time notifications
    cy.get('[data-testid="notifications-icon"]').click();
    cy.get('[data-testid="enable-realtime"]').check();

    // Simulate incoming alert (would be triggered by backend)
    cy.window().then((win) => {
      win.dispatchEvent(new CustomEvent('alert', {
        detail: {
          type: 'FACIAL_RECOGNITION_MATCH',
          targetName: 'Ruja Ignatova',
          location: 'Athens Airport',
          confidence: 0.95,
        },
      }));
    });

    // Verify alert displayed
    cy.get('[data-testid="alert-notification"]')
      .should('be.visible')
      .and('contain', 'Facial Recognition Match')
      .and('contain', 'Ruja Ignatova')
      .and('contain', '95%');

    // Click alert to view details
    cy.get('[data-testid="alert-notification"]').click();

    // Verify alert details page
    cy.url().should('include', '/alerts/');
    cy.get('[data-testid="alert-details"]').should('contain', 'Athens Airport');
  });

  it('should handle blockchain tracking', () => {
    // Login
    cy.get('[data-testid="email-input"]').type(Cypress.env('testUser').email);
    cy.get('[data-testid="password-input"]').type(Cypress.env('testUser').password);
    cy.get('[data-testid="login-button"]').click();

    // Navigate to blockchain tracking
    cy.get('[data-testid="tools-menu"]').click();
    cy.get('[data-testid="blockchain-tracker"]').click();

    // Enter Bitcoin address
    cy.get('[data-testid="address-input"]').type('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');
    cy.get('[data-testid="track-button"]').click();

    // Wait for analysis
    cy.get('[data-testid="loading-spinner"]', { timeout: 10000 }).should('not.exist');

    // Verify results
    cy.get('[data-testid="blockchain-graph"]').should('be.visible');
    cy.get('[data-testid="transaction-count"]').should('exist');
    cy.get('[data-testid="total-value"]').should('exist');

    // View fund flow
    cy.get('[data-testid="fund-flow-tab"]').click();
    cy.get('[data-testid="sankey-diagram"]').should('be.visible');

    // Export results
    cy.get('[data-testid="export-button"]').click();
    cy.get('[data-testid="export-format"]').select('PDF');
    cy.get('[data-testid="confirm-export"]').click();

    // Verify download
    cy.readFile('cypress/downloads/blockchain-analysis.pdf').should('exist');
  });
});
