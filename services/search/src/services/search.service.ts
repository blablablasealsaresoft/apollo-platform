import { Client } from '@elastic/elasticsearch';
import { config, logger } from '@apollo/shared';

export class SearchService {
  private client: Client;

  constructor() {
    this.client = new Client({ node: config.elasticsearch.node });
  }

  async initialize(): Promise<void> {
    try {
      await this.client.ping();
      logger.info('Connected to Elasticsearch');
      await this.createIndices();
    } catch (error) {
      logger.error('Failed to connect to Elasticsearch:', error);
    }
  }

  async createIndices(): Promise<void> {
    const indices = ['investigations', 'targets', 'intelligence', 'evidence'];

    for (const index of indices) {
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
    }
  }

  async indexDocument(index: string, id: string, document: any): Promise<void> {
    await this.client.index({
      index,
      id,
      document,
      refresh: true,
    });
    logger.info(`Indexed document ${id} in ${index}`);
  }

  async search(indices: string[], query: string, filters?: any): Promise<any> {
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
        must.push({ term: { [key]: value } });
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
  }

  async suggest(index: string, field: string, prefix: string): Promise<string[]> {
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
  }

  async deleteDocument(index: string, id: string): Promise<void> {
    await this.client.delete({
      index,
      id,
      refresh: true,
    });
    logger.info(`Deleted document ${id} from ${index}`);
  }

  async healthCheck(): Promise<boolean> {
    try {
      await this.client.ping();
      return true;
    } catch (error) {
      return false;
    }
  }
}

export const searchService = new SearchService();
