export interface Operation {
  id: string;
  title: string;
  status: 'planning' | 'active' | 'complete';
  priority: 'low' | 'medium' | 'high';
}
