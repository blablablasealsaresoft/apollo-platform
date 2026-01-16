import { enqueue } from '../queue/notification.queue';

export function scheduleNotification(channel: 'email' | 'sms', payload: Record<string, unknown>) {
  enqueue({
    id: `job-${Date.now()}`,
    channel,
    payload,
  });
}
