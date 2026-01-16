export interface NotificationJob {
  id: string;
  channel: 'email' | 'sms' | 'push';
  payload: Record<string, unknown>;
}

const jobs: NotificationJob[] = [];

export function enqueue(job: NotificationJob) {
  jobs.push(job);
}

export function dequeue(): NotificationJob | undefined {
  return jobs.shift();
}
