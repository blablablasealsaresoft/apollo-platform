import { Client } from '@elastic/elasticsearch';
import { config, logger, ServiceUnavailableError, BadRequestError, NotFoundError, InternalServerError } from '@apollo/shared';

// Error codes for search service
export const SEARCH_ERROR_CODES = {
  CONNECTION_FAILED: 'SEARCH_CONNECTION_FAILED',
  INDEX_ERROR: 'SEARCH_INDEX_ERROR',
  QUERY_ERROR: 'SEARCH_QUERY_ERROR',
  DOCUMENT_NOT_FOUND: 'SEARCH_DOCUMENT_NOT_FOUND',
  INVALID_QUERY: 'SEARCH_INVALID_QUERY',
  TIMEOUT: 'SEARCH_TIMEOUT',
  SERVICE_UNAVAILABLE: 'SEARCH_SERVICE_UNAVAILABLE',
} as const;

export class SearchService {
  private client: Client;
  private isConnected: boolean = false;

  constructor() {
    this.client = new Client({
      node: config.elasticsearch.node,
      requestTimeout: 30000,
      maxRetries: 3,
    });
  }

  async initialize(): Promise<void> {
    try {
      await this.client.ping();
      this.isConnected = true;
      logger.info('Connected to Elasticsearch');
      await this.createIndices();
    } catch (error) {
      this.isConnected = false;
      logger.error('Failed to connect to Elasticsearch:', error);
      throw new ServiceUnavailableError(
        'Elasticsearch connection failed. Search service unavailable.',
        SEARCH_ERROR_CODES.CONNECTION_FAILED
      );
    }
  }

  private ensureConnected(): void {
    if (!this.isConnected) {
      throw new ServiceUnavailableError(
        'Search service is not connected to Elasticsearch',
        SEARCH_ERROR_CODES.SERVICE_UNAVAILABLE
      );
    }
  }

  async createIndices(): Promise<void> {
    const indices = ['investigations', 'targets', 'intelligence', 'evidence'];

    for (const index of indices) {
      try {
        const exists = await this.client.indices.exists({ index });
        if (!exists) {
          await this.client.indices.create({
            index,
            body: {
              mappings: {
                properties: {
                  id: { type: 'keyword' },
                  title: { type: 'text' },
                  content: { type: 'text' },
                  description: { type: 'text' },
                  tags: { type: 'keyword' },
                  created_at: { type: 'date' },
                  updated_at: { type: 'date' },
                },
              },
            },
          });
          logger.info(`Created index: ${index}`);
        }
      } catch (error: any) {
        logger.error(`Failed to create index ${index}: ${error.message}`);
        // Continue with other indices even if one fails
      }
    }
  }

  async indexDocument(index: string, id: string, document: any): Promise<void> {
    this.ensureConnected();

    if (!index || !id) {
      throw new BadRequestError('Index and document ID are required', SEARCH_ERROR_CODES.INVALID_QUERY);
    }

    try {
      await this.client.index({
        index,
        id,
        document,
        refresh: true,
      });
      logger.info(`Indexed document ${id} in ${index}`);
    } catch (error: any) {
      logger.error(`Failed to index document ${id} in ${index}: ${error.message}`);
      if (error.statusCode === 404) {
        throw new NotFoundError(`Index '${index}' not found`, SEARCH_ERROR_CODES.INDEX_ERROR);
      }
      throw new InternalServerError(
        `Failed to index document: ${error.message}`,
        SEARCH_ERROR_CODES.INDEX_ERROR
      );
    }
  }

  async search(indices: string[], query: string, filters?: any): Promise<any> {
    this.ensureConnected();

    if (!query || query.trim().length === 0) {
      throw new BadRequestError('Search query is required', SEARCH_ERROR_CODES.INVALID_QUERY);
    }

    if (!indices || indices.length === 0) {
      throw new BadRequestError('At least one index must be specified', SEARCH_ERROR_CODES.INVALID_QUERY);
    }

    try {
      const must: any[] = [
        {
          multi_match: {
            query,
            fields: ['title^2', 'content', 'description', 'tags'],
            fuzziness: 'AUTO',
          },
        },
      ];

      if (filters) {
        Object.entries(filters).forEach(([key, value]) => {
          if (value !== undefined && value !== null) {
            must.push({ term: { [key]: value } });
          }
        });
      }

      const result = await this.client.search({
        index: indices,
        body: {
          query: {
            bool: { must },
          },
          highlight: {
            fields: {
              title: {},
              content: {},
              description: {},
            },
          },
          size: 50,
        },
      });

      return {
        total: result.hits.total,
        hits: result.hits.hits.map((hit: any) => ({
          id: hit._id,
          index: hit._index,
          score: hit._score,
          source: hit._source,
          highlights: hit.highlight,
        })),
      };
    } catch (error: any) {
      logger.error(`Search query failed: ${error.message}`);
      if (error.statusCode === 408 || error.name === 'TimeoutError') {
        throw new ServiceUnavailableError('Search request timed out', SEARCH_ERROR_CODES.TIMEOUT);
      }
      if (error.statusCode === 400) {
        throw new BadRequestError(`Invalid search query: ${error.message}`, SEARCH_ERROR_CODES.INVALID_QUERY);
      }
      throw new InternalServerError(
        `Search operation failed: ${error.message}`,
        SEARCH_ERROR_CODES.QUERY_ERROR
      );
    }
  }

  async suggest(index: string, field: string, prefix: string): Promise<string[]> {
    this.ensureConnected();

    if (!prefix || prefix.trim().length === 0) {
      return [];
    }

    try {
      const result = await this.client.search({
        index,
        body: {
          suggest: {
            suggestions: {
              prefix,
              completion: {
                field,
                skip_duplicates: true,
                size: 10,
              },
            },
          },
        },
      });

      return result.suggest?.suggestions?.[0]?.options?.map((opt: any) => opt.text) || [];
    } catch (error: any) {
      logger.error(`Suggestion query failed: ${error.message}`);
      // Return empty suggestions on error rather than failing
      return [];
    }
  }

  async deleteDocument(index: string, id: string): Promise<void> {
    this.ensureConnected();

    if (!index || !id) {
      throw new BadRequestError('Index and document ID are required', SEARCH_ERROR_CODES.INVALID_QUERY);
    }

    try {
      await this.client.delete({
        index,
        id,
        refresh: true,
      });
      logger.info(`Deleted document ${id} from ${index}`);
    } catch (error: any) {
      if (error.statusCode === 404) {
        throw new NotFoundError(`Document '${id}' not found in index '${index}'`, SEARCH_ERROR_CODES.DOCUMENT_NOT_FOUND);
      }
      logger.error(`Failed to delete document ${id} from ${index}: ${error.message}`);
      throw new InternalServerError(
        `Failed to delete document: ${error.message}`,
        SEARCH_ERROR_CODES.INDEX_ERROR
      );
    }
  }

  async healthCheck(): Promise<{ healthy: boolean; details?: string }> {
    try {
      await this.client.ping();
      this.isConnected = true;
      return { healthy: true };
    } catch (error: any) {
      this.isConnected = false;
      return { healthy: false, details: error.message };
    }
  }
}

export const searchService = new SearchService();
