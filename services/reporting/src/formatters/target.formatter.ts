/**
 * Apollo Target Formatter
 *
 * Formats target profile data for report generation.
 * Supports:
 * - Target dossiers
 * - Associate networks
 * - Financial profiles
 * - Digital footprints
 * - Threat assessments
 */

import {
  ReportGenerationOptions,
  ClassificationMarking,
  ReportSection,
  ReportTable,
  ReportChart,
  ReportImage,
  TargetProfileData,
  AliasRecord,
  LocationRecord,
  AssociateRecord,
  FinancialProfile,
  DigitalFootprint,
  ThreatAssessment,
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
  images?: ReportImage[];
  footer?: string;
  metadata?: Record<string, any>;
}

export class TargetFormatter {
  /**
   * Format target profile data for report generation
   */
  formatTargetProfile(
    data: TargetProfileData,
    options: ReportGenerationOptions
  ): FormattedReportData {
    const sections: ReportSection[] = [];
    const tables: ReportTable[] = [];
    const charts: ReportChart[] = [];
    const images: ReportImage[] = [];

    const target = data.target;

    // Executive Summary
    sections.push({
      id: generateId(),
      title: 'Executive Summary',
      content: this.generateTargetExecutiveSummary(data),
      order: 1,
      pageBreakAfter: true,
    });

    // Personal Information Section
    if (data.personalInfo) {
      sections.push({
        id: generateId(),
        title: 'Personal Information',
        content: this.formatPersonalInfo(data.personalInfo),
        order: 2,
        pageBreakBefore: true,
      });
    }

    // Aliases Section
    if (data.aliases && data.aliases.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Known Aliases',
        content: `${data.aliases.length} known alias(es) have been identified for this target.`,
        order: 3,
      });

      tables.push({
        id: generateId(),
        title: 'Alias Records',
        headers: ['Alias', 'Type', 'Confidence', 'Source', 'First Seen', 'Last Seen'],
        rows: data.aliases.map((a) => [
          a.alias,
          a.type.replace('_', ' '),
          a.confidence,
          a.source,
          a.dateFirstSeen ? this.formatDate(a.dateFirstSeen) : 'Unknown',
          a.dateLastSeen ? this.formatDate(a.dateLastSeen) : 'Active',
        ]),
        striped: true,
        bordered: true,
      });

      // Alias type distribution
      const aliasTypeCounts = this.countByField(data.aliases, 'type');
      charts.push({
        id: generateId(),
        type: 'pie',
        title: 'Aliases by Type',
        data: {
          labels: Object.keys(aliasTypeCounts).map((t) => t.replace('_', ' ')),
          values: Object.values(aliasTypeCounts),
        },
      });
    }

    // Known Locations Section
    if (data.knownLocations && data.knownLocations.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Known Locations',
        content: this.formatLocationsNarrative(data.knownLocations),
        order: 4,
        pageBreakBefore: true,
      });

      tables.push({
        id: generateId(),
        title: 'Location History',
        headers: ['Location', 'Type', 'Confidence', 'First Seen', 'Last Seen', 'Source'],
        rows: data.knownLocations.map((l) => [
          `${l.city}, ${l.country}${l.address ? ` (${l.address})` : ''}`,
          l.type.replace('_', ' '),
          l.confidence,
          l.dateFirstSeen ? this.formatDate(l.dateFirstSeen) : 'Unknown',
          l.dateLastSeen ? this.formatDate(l.dateLastSeen) : 'Current',
          l.source,
        ]),
        striped: true,
        bordered: true,
      });

      // Location by country chart
      const countryCounts = this.countByField(data.knownLocations, 'country');
      charts.push({
        id: generateId(),
        type: 'bar',
        title: 'Locations by Country',
        data: {
          labels: Object.keys(countryCounts),
          values: Object.values(countryCounts),
        },
      });
    }

    // Associates Section
    if (data.associates && data.associates.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Known Associates',
        content: this.formatAssociatesNarrative(data.associates),
        order: 5,
        pageBreakBefore: true,
      });

      tables.push({
        id: generateId(),
        title: 'Associate Network',
        headers: ['Name', 'Relationship', 'Strength', 'Direction', 'First Contact', 'Last Contact'],
        rows: data.associates.map((a) => [
          a.name,
          a.relationship,
          a.strength.toUpperCase(),
          a.direction,
          a.dateFirstSeen ? this.formatDate(a.dateFirstSeen) : 'Unknown',
          a.dateLastSeen ? this.formatDate(a.dateLastSeen) : 'Current',
        ]),
        striped: true,
        bordered: true,
      });

      // Associate network visualization
      charts.push({
        id: generateId(),
        type: 'network',
        title: 'Associate Network Map',
        data: {
          nodes: [
            { id: target.id || 'target', label: target.name || 'Target' },
            ...data.associates.map((a) => ({ id: a.id, label: a.name })),
          ],
          edges: data.associates.map((a) => ({
            from: target.id || 'target',
            to: a.id,
          })),
        },
      });

      // Relationship strength distribution
      const strengthCounts = this.countByField(data.associates, 'strength');
      charts.push({
        id: generateId(),
        type: 'pie',
        title: 'Associates by Relationship Strength',
        data: {
          labels: Object.keys(strengthCounts).map((s) => s.toUpperCase()),
          values: Object.values(strengthCounts),
        },
      });
    }

    // Organizations Section
    if (data.organizations && data.organizations.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Organizational Affiliations',
        content: `Target has been linked to ${data.organizations.length} organization(s).`,
        order: 6,
      });

      tables.push({
        id: generateId(),
        title: 'Organizational Links',
        headers: ['Organization', 'Role', 'Active', 'Start Date', 'End Date', 'Source'],
        rows: data.organizations.map((o) => [
          o.organizationName,
          o.role || 'Unknown',
          o.isActive ? 'Yes' : 'No',
          o.startDate ? this.formatDate(o.startDate) : 'Unknown',
          o.endDate ? this.formatDate(o.endDate) : 'Present',
          o.source,
        ]),
        striped: true,
        bordered: true,
      });
    }

    // Financial Profile Section
    if (data.financialProfile) {
      sections.push({
        id: generateId(),
        title: 'Financial Profile',
        content: this.formatFinancialProfile(data.financialProfile),
        order: 7,
        pageBreakBefore: true,
        subsections: this.generateFinancialSubsections(data.financialProfile),
      });

      // Bank accounts table
      if (data.financialProfile.knownBankAccounts && data.financialProfile.knownBankAccounts.length > 0) {
        tables.push({
          id: generateId(),
          title: 'Known Bank Accounts',
          headers: ['Bank', 'Country', 'Account Type', 'Status', 'Last Activity'],
          rows: data.financialProfile.knownBankAccounts.map((acc) => [
            acc.bank,
            acc.country,
            acc.accountType || 'Unknown',
            acc.status.toUpperCase(),
            acc.lastActivity ? this.formatDate(acc.lastActivity) : 'Unknown',
          ]),
          striped: true,
          bordered: true,
        });
      }

      // Crypto wallets table
      if (data.financialProfile.cryptoWallets && data.financialProfile.cryptoWallets.length > 0) {
        tables.push({
          id: generateId(),
          title: 'Cryptocurrency Wallets',
          headers: ['Blockchain', 'Address', 'Balance', 'Last Activity', 'Tags'],
          rows: data.financialProfile.cryptoWallets.map((wallet) => [
            wallet.blockchain,
            wallet.address.substring(0, 16) + '...',
            wallet.balance || 'Unknown',
            wallet.lastActivity ? this.formatDate(wallet.lastActivity) : 'Unknown',
            wallet.tags?.join(', ') || 'None',
          ]),
          striped: true,
          bordered: true,
        });
      }

      // Suspicious transactions
      if (data.financialProfile.suspiciousTransactions && data.financialProfile.suspiciousTransactions.length > 0) {
        tables.push({
          id: generateId(),
          title: 'Suspicious Transactions',
          headers: ['Date', 'Amount', 'Type', 'Counterparty', 'Risk Indicators'],
          rows: data.financialProfile.suspiciousTransactions.map((tx) => [
            this.formatDate(tx.date),
            `${tx.amount} ${tx.currency}`,
            tx.type,
            tx.counterparty || 'Unknown',
            tx.riskIndicators.join(', '),
          ]),
          striped: true,
          bordered: true,
        });
      }
    }

    // Digital Footprint Section
    if (data.digitalFootprint) {
      sections.push({
        id: generateId(),
        title: 'Digital Footprint',
        content: this.formatDigitalFootprint(data.digitalFootprint),
        order: 8,
        pageBreakBefore: true,
      });

      // Social media profiles
      if (data.digitalFootprint.socialMediaProfiles && data.digitalFootprint.socialMediaProfiles.length > 0) {
        tables.push({
          id: generateId(),
          title: 'Social Media Profiles',
          headers: ['Platform', 'Username', 'Followers', 'Verified', 'Last Active'],
          rows: data.digitalFootprint.socialMediaProfiles.map((profile) => [
            profile.platform,
            profile.username,
            profile.followers?.toString() || 'N/A',
            profile.verified ? 'Yes' : 'No',
            profile.lastActive ? this.formatDate(profile.lastActive) : 'Unknown',
          ]),
          striped: true,
          bordered: true,
        });
      }

      // IP addresses
      if (data.digitalFootprint.ipAddresses && data.digitalFootprint.ipAddresses.length > 0) {
        tables.push({
          id: generateId(),
          title: 'Known IP Addresses',
          headers: ['IP Address', 'Type', 'Location', 'ISP', 'First Seen', 'Last Seen'],
          rows: data.digitalFootprint.ipAddresses.map((ip) => [
            ip.address,
            ip.type.toUpperCase(),
            ip.geolocation ? `${ip.geolocation.city || 'Unknown'}, ${ip.geolocation.country}` : 'Unknown',
            ip.isp || 'Unknown',
            this.formatDate(ip.firstSeen),
            this.formatDate(ip.lastSeen),
          ]),
          striped: true,
          bordered: true,
        });
      }
    }

    // Threat Assessment Section
    if (data.threatAssessment) {
      sections.push({
        id: generateId(),
        title: 'Threat Assessment',
        content: this.formatThreatAssessment(data.threatAssessment),
        order: 9,
        pageBreakBefore: true,
      });
    }

    // Operational History Section
    if (data.operationalHistory && data.operationalHistory.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Operational History',
        content: `${data.operationalHistory.length} operational event(s) have been recorded for this target.`,
        order: 10,
        pageBreakBefore: true,
      });

      tables.push({
        id: generateId(),
        title: 'Operational Events',
        headers: ['Date', 'Type', 'Description', 'Outcome', 'Related Entities'],
        rows: data.operationalHistory.map((event) => [
          this.formatDate(event.date),
          event.type,
          event.description.substring(0, 40) + '...',
          event.outcome || 'N/A',
          event.relatedEntities?.join(', ') || 'None',
        ]),
        striped: true,
        bordered: true,
      });

      // Timeline chart for operational history
      charts.push({
        id: generateId(),
        type: 'timeline',
        title: 'Operational History Timeline',
        data: {
          events: data.operationalHistory.slice(0, 15).map((event) => ({
            date: this.formatDate(event.date),
            title: event.type,
            description: event.description,
          })),
        },
      });
    }

    // Photos Section
    if (data.photos && data.photos.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Photographic Evidence',
        content: `${data.photos.length} photograph(s) are associated with this target.`,
        order: 11,
      });

      images.push(
        ...data.photos.map((photo) => ({
          id: photo.id,
          path: photo.path,
          caption: photo.caption,
          width: photo.width,
          height: photo.height,
        }))
      );
    }

    // Intelligence Reports Section
    if (data.intelligence && data.intelligence.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Related Intelligence',
        content: `${data.intelligence.length} intelligence report(s) reference this target.`,
        order: 12,
      });

      tables.push({
        id: generateId(),
        title: 'Intelligence Reports',
        headers: ['Report ID', 'Title', 'Classification', 'Date'],
        rows: data.intelligence.map((intel: any) => [
          intel.id?.substring(0, 8) || 'N/A',
          intel.title || 'Untitled',
          intel.classification || options.classification,
          this.formatDate(intel.created_at || new Date()),
        ]),
        striped: true,
        bordered: true,
      });
    }

    return {
      title: `Target Profile: ${target.name || 'Unknown Subject'}`,
      subtitle: target.codename ? `Codename: ${target.codename}` : undefined,
      classification: options.classification,
      generatedDate: new Date(),
      sections,
      tables,
      charts,
      images,
      footer: `Target ID: ${target.id}`,
      metadata: {
        reportId: generateId(),
        targetId: target.id,
        type: 'target_profile',
        threatLevel: data.threatAssessment?.overallThreatLevel,
      },
    };
  }

  // Helper methods

  private generateTargetExecutiveSummary(data: TargetProfileData): string {
    const target = data.target;
    const threatLevel = data.threatAssessment?.overallThreatLevel || 'unknown';

    return `This report provides a comprehensive profile of target "${target.name || 'Unknown'}" (ID: ${target.id}).

TARGET OVERVIEW
Status: ${target.status || 'Unknown'}
Type: ${target.type || 'Person'}
Risk Level: ${target.risk_level || 'Not Assessed'}
Threat Assessment: ${threatLevel.toUpperCase()}

PROFILE SUMMARY
Known Aliases: ${data.aliases?.length || 0}
Known Locations: ${data.knownLocations?.length || 0}
Known Associates: ${data.associates?.length || 0}
Organizational Links: ${data.organizations?.length || 0}
Intelligence Reports: ${data.intelligence?.length || 0}

${data.financialProfile ? `FINANCIAL INDICATORS
Estimated Net Worth: ${data.financialProfile.estimatedNetWorth || 'Unknown'}
Known Bank Accounts: ${data.financialProfile.knownBankAccounts?.length || 0}
Cryptocurrency Wallets: ${data.financialProfile.cryptoWallets?.length || 0}
Suspicious Transactions: ${data.financialProfile.suspiciousTransactions?.length || 0}` : ''}`;
  }

  private formatPersonalInfo(info: any): string {
    let content = `Full Name: ${info.fullName}\n`;

    if (info.dateOfBirth) {
      content += `Date of Birth: ${this.formatDate(info.dateOfBirth)}\n`;
    }
    if (info.placeOfBirth) {
      content += `Place of Birth: ${info.placeOfBirth}\n`;
    }
    if (info.nationality && info.nationality.length > 0) {
      content += `Nationality: ${info.nationality.join(', ')}\n`;
    }
    if (info.gender) {
      content += `Gender: ${info.gender}\n`;
    }
    if (info.physicalDescription) {
      content += `\nPhysical Description:\n${info.physicalDescription}\n`;
    }

    if (info.identificationDocuments && info.identificationDocuments.length > 0) {
      content += `\nIdentification Documents:\n`;
      info.identificationDocuments.forEach((doc: any, i: number) => {
        content += `${i + 1}. ${doc.type} (${doc.issuingCountry}): ${doc.number} - Status: ${doc.status.toUpperCase()}\n`;
      });
    }

    return content;
  }

  private formatLocationsNarrative(locations: LocationRecord[]): string {
    const currentLocations = locations.filter((l) => l.type === 'residence' || l.type === 'frequent');
    const countries = [...new Set(locations.map((l) => l.country))];

    let narrative = `Target has been observed in ${countries.length} country/countries: ${countries.join(', ')}.\n\n`;

    if (currentLocations.length > 0) {
      narrative += `Current known locations include:\n`;
      currentLocations.forEach((loc) => {
        narrative += `- ${loc.city}, ${loc.country} (${loc.type.replace('_', ' ')}, confidence: ${loc.confidence})\n`;
      });
    }

    return narrative;
  }

  private formatAssociatesNarrative(associates: AssociateRecord[]): string {
    const strongAssociates = associates.filter((a) => a.strength === 'strong');
    const relationships = [...new Set(associates.map((a) => a.relationship))];

    let narrative = `Target has ${associates.length} known associate(s) across ${relationships.length} relationship type(s).\n\n`;

    if (strongAssociates.length > 0) {
      narrative += `Strong associations:\n`;
      strongAssociates.forEach((assoc) => {
        narrative += `- ${assoc.name} (${assoc.relationship})\n`;
      });
    }

    return narrative;
  }

  private formatFinancialProfile(profile: FinancialProfile): string {
    let content = `Estimated Net Worth: ${profile.estimatedNetWorth || 'Unknown'}\n\n`;

    content += `Financial Assets Summary:\n`;
    content += `- Bank Accounts: ${profile.knownBankAccounts?.length || 0}\n`;
    content += `- Cryptocurrency Wallets: ${profile.cryptoWallets?.length || 0}\n`;
    content += `- Properties: ${profile.properties?.length || 0}\n`;
    content += `- Companies: ${profile.companies?.length || 0}\n`;
    content += `- Suspicious Transactions: ${profile.suspiciousTransactions?.length || 0}\n`;

    return content;
  }

  private generateFinancialSubsections(profile: FinancialProfile): ReportSection[] {
    const subsections: ReportSection[] = [];

    if (profile.properties && profile.properties.length > 0) {
      subsections.push({
        id: generateId(),
        title: 'Property Holdings',
        content: profile.properties
          .map(
            (p) =>
              `${p.type} in ${p.location}${p.estimatedValue ? ` (Est. ${p.estimatedValue})` : ''} - ${p.ownershipType.replace('_', ' ')} ownership`
          )
          .join('\n'),
        order: 1,
      });
    }

    if (profile.companies && profile.companies.length > 0) {
      subsections.push({
        id: generateId(),
        title: 'Company Affiliations',
        content: profile.companies
          .map(
            (c) =>
              `${c.name} (${c.jurisdiction}) - ${c.role}, Status: ${c.status}${c.isShellCompany ? ' [SUSPECTED SHELL COMPANY]' : ''}`
          )
          .join('\n'),
        order: 2,
      });
    }

    return subsections;
  }

  private formatDigitalFootprint(footprint: DigitalFootprint): string {
    let content = 'DIGITAL PRESENCE SUMMARY\n\n';

    if (footprint.domains && footprint.domains.length > 0) {
      content += `Registered Domains: ${footprint.domains.join(', ')}\n\n`;
    }

    if (footprint.emailAddresses && footprint.emailAddresses.length > 0) {
      content += `Known Email Addresses: ${footprint.emailAddresses.join(', ')}\n\n`;
    }

    if (footprint.phoneNumbers && footprint.phoneNumbers.length > 0) {
      content += `Known Phone Numbers: ${footprint.phoneNumbers.join(', ')}\n\n`;
    }

    content += `Social Media Profiles: ${footprint.socialMediaProfiles?.length || 0}\n`;
    content += `Known IP Addresses: ${footprint.ipAddresses?.length || 0}\n`;
    content += `Associated Devices: ${footprint.devices?.length || 0}\n`;

    return content;
  }

  private formatThreatAssessment(assessment: ThreatAssessment): string {
    let content = `OVERALL THREAT LEVEL: ${assessment.overallThreatLevel.toUpperCase()}\n\n`;

    if (assessment.capabilities && assessment.capabilities.length > 0) {
      content += `Known Capabilities:\n`;
      assessment.capabilities.forEach((cap, i) => {
        content += `${i + 1}. ${cap}\n`;
      });
      content += '\n';
    }

    if (assessment.intentions) {
      content += `Assessed Intentions:\n${assessment.intentions}\n\n`;
    }

    if (assessment.opportunities && assessment.opportunities.length > 0) {
      content += `Potential Opportunities:\n`;
      assessment.opportunities.forEach((opp, i) => {
        content += `${i + 1}. ${opp}\n`;
      });
      content += '\n';
    }

    if (assessment.vulnerabilities && assessment.vulnerabilities.length > 0) {
      content += `Known Vulnerabilities:\n`;
      assessment.vulnerabilities.forEach((vuln, i) => {
        content += `${i + 1}. ${vuln}\n`;
      });
      content += '\n';
    }

    if (assessment.projectedActions && assessment.projectedActions.length > 0) {
      content += `Projected Actions:\n`;
      assessment.projectedActions.forEach((action, i) => {
        content += `${i + 1}. ${action}\n`;
      });
    }

    return content;
  }

  private countByField(items: any[], field: string): Record<string, number> {
    return items.reduce(
      (acc, item) => {
        const value = item[field];
        acc[value] = (acc[value] || 0) + 1;
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
}

export const targetFormatter = new TargetFormatter();
