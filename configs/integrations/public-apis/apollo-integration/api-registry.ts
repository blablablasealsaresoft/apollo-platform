/**
 * API Registry - Manage registry of 1000+ APIs
 *
 * @module APIRegistry
 * @elite-engineering
 */

import * as fs from 'fs';
import * as path from 'path';

export class APIRegistry {
  private apis: Map<string, any>;
  private categories: Map<string, any[]>;

  constructor() {
    this.apis = new Map();
    this.categories = new Map();
  }

  async loadFromFile(filename: string): Promise<void> {
    const registryPath = path.join(__dirname, '..', filename);
    const data = JSON.parse(fs.readFileSync(registryPath, 'utf-8'));

    // Load all APIs from registry
    for (const [category, categoryData] of Object.entries(data.categories as any)) {
      const apis = (categoryData as any).apis || [];
      apis.forEach((api: any) => {
        api.category = category;
        this.apis.set(api.id, api);
      });

      if (!this.categories.has(category)) {
        this.categories.set(category, []);
      }
      this.categories.get(category)!.push(...apis);
    }
  }

  async loadCategories(categories: string[]): Promise<void> {
    // Load category YAML files
  }

  getAPI(apiId: string): any {
    return this.apis.get(apiId);
  }

  getAllAPIs(): any[] {
    return Array.from(this.apis.values());
  }

  getAllAPIsWithMetadata(): any[] {
    return this.getAllAPIs();
  }

  getTotalAPIs(): number {
    return this.apis.size;
  }

  getTotalCategories(): number {
    return this.categories.size;
  }

  getAPIsByCategory(category: string): any[] {
    return this.categories.get(category) || [];
  }
}

export const apiRegistry = new APIRegistry();
