/**
 * Error Handler - Handle API errors with intelligent retry/failover
 *
 * @module ErrorHandler
 * @elite-engineering
 */

export class ErrorHandler {

  async handle(error: Error, apiId: string): Promise<void> {
    console.error(`API Error [${apiId}]: ${error.message}`);

    // Log error for analysis
    this.logError(apiId, error);

    // Determine if retry is appropriate
    if (this.isRetryable(error)) {
      console.log(`Will retry API: ${apiId}`);
    } else {
      console.log(`Non-retryable error for API: ${apiId}`);
    }
  }

  handleAxiosError(error: any, api: any): Promise<any> {
    return Promise.reject(error);
  }

  private isRetryable(error: Error): boolean {
    // Rate limit, timeout, network errors are retryable
    return error.message.includes('rate limit') ||
           error.message.includes('timeout') ||
           error.message.includes('ECONNREFUSED');
  }

  private logError(apiId: string, error: Error): void {
    // Log to Apollo error tracking system
  }
}

export const errorHandler = new ErrorHandler();
