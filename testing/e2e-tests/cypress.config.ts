import { defineConfig } from 'cypress';

export default defineConfig({
  e2e: {
    baseUrl: 'http://localhost:3000',
    supportFile: 'testing/e2e-tests/support/e2e.ts',
    specPattern: 'testing/e2e-tests/**/*.cy.{js,jsx,ts,tsx}',
    videosFolder: 'testing/e2e-tests/videos',
    screenshotsFolder: 'testing/e2e-tests/screenshots',
    downloadsFolder: 'testing/e2e-tests/downloads',
    fixturesFolder: 'testing/e2e-tests/fixtures',

    setupNodeEvents(on, config) {
      // implement node event listeners here
      on('task', {
        log(message) {
          console.log(message);
          return null;
        },
        clearDatabase() {
          // Clear test database
          return null;
        },
        seedDatabase() {
          // Seed test data
          return null;
        },
      });

      return config;
    },

    env: {
      apiUrl: 'http://localhost:3000/api',
      testUser: {
        email: 'analyst@test.com',
        password: 'TestPassword123!',
      },
    },

    viewportWidth: 1920,
    viewportHeight: 1080,
    video: true,
    videoCompression: 32,
    screenshotOnRunFailure: true,
    trashAssetsBeforeRuns: true,

    defaultCommandTimeout: 10000,
    requestTimeout: 10000,
    responseTimeout: 10000,
    pageLoadTimeout: 30000,

    retries: {
      runMode: 2,
      openMode: 0,
    },

    experimentalStudio: true,
    experimentalWebKitSupport: false,
  },

  component: {
    devServer: {
      framework: 'react',
      bundler: 'vite',
    },
    supportFile: 'testing/e2e-tests/support/component.ts',
    specPattern: 'frontend/**/*.cy.{js,jsx,ts,tsx}',
  },
});
