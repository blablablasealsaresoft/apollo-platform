/**
 * Apollo Timeline Formatter
 *
 * Formats timeline and chronological data for report generation.
 * Supports:
 * - Investigation timelines
 * - Target activity timelines
 * - Operation timelines
 * - Event correlation timelines
 */

import {
  ReportGenerationOptions,
  ClassificationMarking,
  ReportSection,
  ReportTable,
  ReportChart,
  TimelineEvent,
} from '../types';
import { generateId } from '@apollo/shared';

interface FormattedReportData {
  title: string;
  subtitle?: string;
  classification: ClassificationMarking;
  generatedDate: Date;
  author?: string;
  sections: ReportSection[];
  tables?: ReportTable[];
  charts?: ReportChart[];
  footer?: string;
  metadata?: Record<string, any>;
}

interface TimelineData {
  events: TimelineEvent[];
  parameters: {
    entityId?: string;
    entityType?: string;
    startDate?: Date;
    endDate?: Date;
    title?: string;
  };
}

interface TimelineGroup {
  period: string;
  events: TimelineEvent[];
}

export class TimelineFormatter {
  /**
   * Format timeline data for report generation
   */
  formatTimeline(
    data: TimelineData,
    options: ReportGenerationOptions
  ): FormattedReportData {
    const sections: ReportSection[] = [];
    const tables: ReportTable[] = [];
    const charts: ReportChart[] = [];

    const events = this.sortEventsByDate(data.events);
    const title = data.parameters.title || 'Timeline Report';

    // Executive Summary
    sections.push({
      id: generateId(),
      title: 'Timeline Overview',
      content: this.generateTimelineOverview(events, data.parameters),
      order: 1,
    });

    // Timeline Statistics
    sections.push({
      id: generateId(),
      title: 'Timeline Statistics',
      content: this.generateTimelineStatistics(events),
      order: 2,
    });

    // Event type distribution chart
    const eventTypeCounts = this.countByField(events, 'type');
    if (Object.keys(eventTypeCounts).length > 0) {
      charts.push({
        id: generateId(),
        type: 'pie',
        title: 'Events by Type',
        data: {
          labels: Object.keys(eventTypeCounts),
          values: Object.values(eventTypeCounts),
        },
      });
    }

    // Events over time chart
    const eventsOverTime = this.groupEventsByMonth(events);
    if (eventsOverTime.length > 0) {
      charts.push({
        id: generateId(),
        type: 'line',
        title: 'Events Over Time',
        data: {
          labels: eventsOverTime.map((g) => g.period),
          values: eventsOverTime.map((g) => g.events.length),
        },
      });
    }

    // Visual timeline
    if (events.length > 0) {
      charts.push({
        id: generateId(),
        type: 'timeline',
        title: 'Event Timeline',
        data: {
          events: events.slice(0, 30).map((e) => ({
            date: this.formatDate(e.timestamp),
            title: e.title,
            description: e.description,
          })),
        },
      });
    }

    // Chronological Narrative
    sections.push({
      id: generateId(),
      title: 'Chronological Narrative',
      content: this.generateChronologicalNarrative(events),
      order: 3,
      pageBreakBefore: true,
    });

    // Group events by time period (e.g., months or years)
    const groupedEvents = this.groupEventsByTimePeriod(events, data.parameters);

    groupedEvents.forEach((group, index) => {
      sections.push({
        id: generateId(),
        title: group.period,
        content: this.formatEventGroupNarrative(group.events),
        order: 4 + index,
        pageBreakBefore: index === 0,
      });

      // Table for this period
      tables.push({
        id: generateId(),
        title: `Events - ${group.period}`,
        headers: ['Date/Time', 'Event', 'Type', 'Actors', 'Location', 'Confidence'],
        rows: group.events.map((e) => [
          this.formatDateTime(e.timestamp),
          e.title,
          e.type,
          e.actors?.join(', ') || 'N/A',
          e.location || 'Unknown',
          e.confidence || 'N/A',
        ]),
        striped: true,
        bordered: true,
      });
    });

    // Actor Analysis
    const actors = this.extractActors(events);
    if (actors.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Actor Analysis',
        content: this.formatActorAnalysis(events, actors),
        order: 4 + groupedEvents.length,
        pageBreakBefore: true,
      });

      tables.push({
        id: generateId(),
        title: 'Actor Activity Summary',
        headers: ['Actor', 'Event Count', 'First Activity', 'Last Activity', 'Primary Event Types'],
        rows: actors.slice(0, 20).map((actor) => {
          const actorEvents = events.filter((e) => e.actors?.includes(actor));
          const eventTypes = [...new Set(actorEvents.map((e) => e.type))];
          return [
            actor,
            actorEvents.length.toString(),
            actorEvents.length > 0 ? this.formatDate(actorEvents[0].timestamp) : 'N/A',
            actorEvents.length > 0 ? this.formatDate(actorEvents[actorEvents.length - 1].timestamp) : 'N/A',
            eventTypes.slice(0, 3).join(', '),
          ];
        }),
        striped: true,
        bordered: true,
      });
    }

    // Location Analysis
    const locations = this.extractLocations(events);
    if (locations.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Location Analysis',
        content: this.formatLocationAnalysis(events, locations),
        order: 5 + groupedEvents.length,
      });

      // Location frequency chart
      const locationCounts = this.countLocations(events);
      charts.push({
        id: generateId(),
        type: 'bar',
        title: 'Events by Location',
        data: {
          labels: Object.keys(locationCounts).slice(0, 10),
          values: Object.values(locationCounts).slice(0, 10),
        },
      });
    }

    // Key Events Summary
    const keyEvents = this.identifyKeyEvents(events);
    if (keyEvents.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Key Events',
        content: 'The following events have been identified as particularly significant:',
        order: 6 + groupedEvents.length,
        subsections: keyEvents.map((event, index) => ({
          id: generateId(),
          title: `${this.formatDate(event.timestamp)}: ${event.title}`,
          content: `Type: ${event.type}\n${event.description}\n\n${event.actors ? `Actors: ${event.actors.join(', ')}` : ''}${event.location ? `\nLocation: ${event.location}` : ''}`,
          order: index + 1,
        })),
      });
    }

    // Complete Event Table
    sections.push({
      id: generateId(),
      title: 'Complete Event Log',
      content: `Total events: ${events.length}`,
      order: 7 + groupedEvents.length,
      pageBreakBefore: true,
    });

    tables.push({
      id: generateId(),
      title: 'All Events',
      headers: ['ID', 'Date/Time', 'Title', 'Type', 'Description', 'Source', 'Confidence'],
      rows: events.map((e) => [
        e.id.substring(0, 8),
        this.formatDateTime(e.timestamp),
        e.title.substring(0, 30) + (e.title.length > 30 ? '...' : ''),
        e.type,
        e.description.substring(0, 40) + (e.description.length > 40 ? '...' : ''),
        e.source || 'N/A',
        e.confidence || 'N/A',
      ]),
      striped: true,
      bordered: true,
    });

    return {
      title,
      subtitle: data.parameters.entityId ? `Entity: ${data.parameters.entityId}` : undefined,
      classification: options.classification,
      generatedDate: new Date(),
      sections,
      tables,
      charts,
      footer: `Timeline generated from ${events.length} events`,
      metadata: {
        reportId: generateId(),
        entityId: data.parameters.entityId,
        entityType: data.parameters.entityType,
        type: 'timeline',
        eventCount: events.length,
      },
    };
  }

  // Helper methods

  private sortEventsByDate(events: TimelineEvent[]): TimelineEvent[] {
    return [...events].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );
  }

  private generateTimelineOverview(events: TimelineEvent[], parameters: any): string {
    if (events.length === 0) {
      return 'No events found for the specified parameters.';
    }

    const firstEvent = events[0];
    const lastEvent = events[events.length - 1];
    const eventTypes = [...new Set(events.map((e) => e.type))];
    const actorCount = this.extractActors(events).length;
    const locationCount = this.extractLocations(events).length;

    let content = `This timeline report covers ${events.length} event(s) from ${this.formatDate(firstEvent.timestamp)} to ${this.formatDate(lastEvent.timestamp)}.\n\n`;

    content += `SUMMARY METRICS\n`;
    content += `- Total Events: ${events.length}\n`;
    content += `- Event Types: ${eventTypes.length} (${eventTypes.slice(0, 5).join(', ')}${eventTypes.length > 5 ? '...' : ''})\n`;
    content += `- Unique Actors: ${actorCount}\n`;
    content += `- Unique Locations: ${locationCount}\n`;

    if (parameters.entityId) {
      content += `\nEntity Reference: ${parameters.entityId} (${parameters.entityType || 'Unknown Type'})\n`;
    }

    return content;
  }

  private generateTimelineStatistics(events: TimelineEvent[]): string {
    if (events.length === 0) return 'No events to analyze.';

    const eventTypeCounts = this.countByField(events, 'type');
    const mostCommonType = Object.entries(eventTypeCounts).sort((a, b) => b[1] - a[1])[0];

    const eventsWithConfidence = events.filter((e) => e.confidence);
    const highConfidenceCount = eventsWithConfidence.filter(
      (e) => e.confidence === 'high' || e.confidence === 'confirmed'
    ).length;

    let content = 'STATISTICAL ANALYSIS\n\n';

    content += `Event Distribution:\n`;
    Object.entries(eventTypeCounts)
      .sort((a, b) => b[1] - a[1])
      .forEach(([type, count]) => {
        const percentage = ((count / events.length) * 100).toFixed(1);
        content += `- ${type}: ${count} (${percentage}%)\n`;
      });

    content += `\nMost Common Event Type: ${mostCommonType[0]} (${mostCommonType[1]} occurrences)\n`;

    if (eventsWithConfidence.length > 0) {
      content += `\nConfidence Analysis:\n`;
      content += `- Events with confidence rating: ${eventsWithConfidence.length}\n`;
      content += `- High confidence events: ${highConfidenceCount}\n`;
    }

    return content;
  }

  private generateChronologicalNarrative(events: TimelineEvent[]): string {
    if (events.length === 0) return 'No events recorded.';

    let narrative = 'CHRONOLOGICAL SUMMARY\n\n';

    // First event
    narrative += `The timeline begins on ${this.formatDate(events[0].timestamp)} with "${events[0].title}": ${events[0].description}\n\n`;

    // Significant events in between (sample)
    if (events.length > 2) {
      const midIndex = Math.floor(events.length / 2);
      narrative += `Mid-timeline (${this.formatDate(events[midIndex].timestamp)}): "${events[midIndex].title}" - ${events[midIndex].description}\n\n`;
    }

    // Last event
    if (events.length > 1) {
      const lastEvent = events[events.length - 1];
      narrative += `The most recent event occurred on ${this.formatDate(lastEvent.timestamp)}: "${lastEvent.title}" - ${lastEvent.description}\n`;
    }

    return narrative;
  }

  private groupEventsByTimePeriod(events: TimelineEvent[], parameters: any): TimelineGroup[] {
    if (events.length === 0) return [];

    const groups: TimelineGroup[] = [];
    const eventsByMonth: Record<string, TimelineEvent[]> = {};

    events.forEach((event) => {
      const date = new Date(event.timestamp);
      const monthKey = `${date.toLocaleString('en-US', { month: 'long' })} ${date.getFullYear()}`;

      if (!eventsByMonth[monthKey]) {
        eventsByMonth[monthKey] = [];
      }
      eventsByMonth[monthKey].push(event);
    });

    Object.entries(eventsByMonth).forEach(([period, periodEvents]) => {
      groups.push({ period, events: periodEvents });
    });

    return groups;
  }

  private groupEventsByMonth(events: TimelineEvent[]): TimelineGroup[] {
    const groups: Record<string, TimelineEvent[]> = {};

    events.forEach((event) => {
      const date = new Date(event.timestamp);
      const monthKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;

      if (!groups[monthKey]) {
        groups[monthKey] = [];
      }
      groups[monthKey].push(event);
    });

    return Object.entries(groups)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([period, periodEvents]) => ({ period, events: periodEvents }));
  }

  private formatEventGroupNarrative(events: TimelineEvent[]): string {
    let narrative = `${events.length} event(s) recorded during this period.\n\n`;

    const eventTypes = [...new Set(events.map((e) => e.type))];
    narrative += `Event types: ${eventTypes.join(', ')}\n\n`;

    // Summarize first few events
    events.slice(0, 5).forEach((event) => {
      narrative += `${this.formatDateTime(event.timestamp)}: ${event.title}\n${event.description}\n\n`;
    });

    if (events.length > 5) {
      narrative += `... and ${events.length - 5} additional event(s).\n`;
    }

    return narrative;
  }

  private extractActors(events: TimelineEvent[]): string[] {
    const actors = new Set<string>();
    events.forEach((event) => {
      if (event.actors) {
        event.actors.forEach((actor) => actors.add(actor));
      }
    });
    return Array.from(actors);
  }

  private extractLocations(events: TimelineEvent[]): string[] {
    const locations = new Set<string>();
    events.forEach((event) => {
      if (event.location) {
        locations.add(event.location);
      }
    });
    return Array.from(locations);
  }

  private formatActorAnalysis(events: TimelineEvent[], actors: string[]): string {
    let content = `${actors.length} unique actor(s) have been identified in this timeline.\n\n`;

    const actorActivity: Record<string, number> = {};
    actors.forEach((actor) => {
      actorActivity[actor] = events.filter((e) => e.actors?.includes(actor)).length;
    });

    const sortedActors = Object.entries(actorActivity).sort((a, b) => b[1] - a[1]);

    content += 'ACTOR ACTIVITY RANKING:\n';
    sortedActors.slice(0, 10).forEach(([actor, count], index) => {
      content += `${index + 1}. ${actor}: ${count} event(s)\n`;
    });

    return content;
  }

  private formatLocationAnalysis(events: TimelineEvent[], locations: string[]): string {
    let content = `Events occurred across ${locations.length} unique location(s).\n\n`;

    const locationCounts = this.countLocations(events);
    const sortedLocations = Object.entries(locationCounts).sort((a, b) => b[1] - a[1]);

    content += 'LOCATION FREQUENCY:\n';
    sortedLocations.slice(0, 10).forEach(([location, count], index) => {
      content += `${index + 1}. ${location}: ${count} event(s)\n`;
    });

    return content;
  }

  private countLocations(events: TimelineEvent[]): Record<string, number> {
    const counts: Record<string, number> = {};
    events.forEach((event) => {
      if (event.location) {
        counts[event.location] = (counts[event.location] || 0) + 1;
      }
    });
    return counts;
  }

  private identifyKeyEvents(events: TimelineEvent[]): TimelineEvent[] {
    // Identify key events based on various criteria
    const keyEvents: TimelineEvent[] = [];

    // High confidence events
    const highConfidenceEvents = events.filter(
      (e) => e.confidence === 'high' || e.confidence === 'confirmed'
    );
    keyEvents.push(...highConfidenceEvents.slice(0, 5));

    // Events with multiple actors
    const multiActorEvents = events.filter((e) => e.actors && e.actors.length > 2);
    keyEvents.push(...multiActorEvents.slice(0, 3));

    // Unique key events
    const uniqueKeyEvents = Array.from(new Set(keyEvents.map((e) => e.id))).map(
      (id) => keyEvents.find((e) => e.id === id)!
    );

    return uniqueKeyEvents.slice(0, 10);
  }

  private countByField(items: any[], field: string): Record<string, number> {
    return items.reduce(
      (acc, item) => {
        const value = item[field];
        if (value) {
          acc[value] = (acc[value] || 0) + 1;
        }
        return acc;
      },
      {} as Record<string, number>
    );
  }

  private formatDate(date: Date | string): string {
    return new Date(date).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  }

  private formatDateTime(date: Date | string): string {
    return new Date(date).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  }
}

export const timelineFormatter = new TimelineFormatter();
