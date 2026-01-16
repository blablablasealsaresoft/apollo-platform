# Apollo Reporting Service

Professional report generation microservice for the Apollo Intelligence Platform.

## Overview

The Reporting Service generates professional documents across multiple formats with support for classification markings, charts, tables, and various report types tailored for intelligence operations.

## Features

### Report Types

1. **Investigation Summary** - Comprehensive investigation reports with findings, evidence, and recommendations
2. **Target Profile** - Detailed dossiers including personal info, associates, financial profiles, and threat assessments
3. **Evidence Chain** - Chain of custody reports with integrity verification
4. **Intelligence Analysis** - Intelligence reports with assessments, sources, and confidence ratings
5. **Operation After-Action** - Post-operation reviews with lessons learned
6. **Threat Assessment** - Threat analysis reports for targets
7. **Financial Analysis** - Financial profiles with transaction analysis
8. **Network Mapping** - Entity relationship and network analysis
9. **Timeline** - Chronological event timelines
10. **Executive Brief** - High-level summaries for leadership

### Export Formats

- **PDF** - Professional documents with headers, footers, classification banners, and watermarks
- **DOCX** - Microsoft Word documents
- **XLSX** - Excel spreadsheets with multiple worksheets
- **HTML** - Web-ready reports
- **JSON** - Structured data format
- **Markdown** - Plain text with formatting

### Security Features

- Classification markings (TOP SECRET//SCI, TOP SECRET, SECRET, CONFIDENTIAL, etc.)
- Handling instructions based on classification level
- Watermarks
- PDF encryption support
- Clearance-based access control

## API Endpoints

### Report Generation

```
POST /api/v1/reports/generate
```

Generate a new report.

**Request Body:**
```json
{
  "type": "investigation_summary",
  "format": "pdf",
  "title": "Investigation Report - Operation ALPHA",
  "parameters": {
    "investigationId": "inv-123-456"
  },
  "options": {
    "classification": "SECRET",
    "includeTableOfContents": true,
    "includePageNumbers": true,
    "includeWatermark": true
  }
}
```

### List Reports

```
GET /api/v1/reports
```

List all generated reports with optional filtering.

**Query Parameters:**
- `type` - Filter by report type
- `status` - Filter by status (queued, generating, completed, failed)
- `limit` - Number of results (default: 50, max: 100)
- `offset` - Pagination offset

### Get Report

```
GET /api/v1/reports/:id
```

Get report details and status.

### Download Report

```
GET /api/v1/reports/:id/download
```

Download the generated report file.

### Get Templates

```
GET /api/v1/reports/templates
GET /api/v1/reports/templates/:type
```

Get available report templates.

### Get Report Types

```
GET /api/v1/reports/types
```

Get available report types with their required and optional parameters.

### Report Schedules

```
POST /api/v1/reports/schedules
```

Create scheduled report generation.

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Service port | 3008 |
| `NODE_ENV` | Environment | development |
| `REPORTS_DIR` | Report storage directory | /tmp/apollo-reports |
| `CORS_ORIGIN` | Allowed CORS origins | * |

## Project Structure

```
services/reporting/
├── src/
│   ├── index.ts                 # Service entry point
│   ├── types/
│   │   └── index.ts             # TypeScript type definitions
│   ├── routes/
│   │   └── report.routes.ts     # API route handlers
│   ├── services/
│   │   └── report.service.ts    # Core report service
│   ├── generators/
│   │   └── report.generator.ts  # Report generation orchestrator
│   ├── formatters/
│   │   ├── index.ts             # Formatter exports
│   │   ├── case.formatter.ts    # Investigation/evidence formatters
│   │   ├── target.formatter.ts  # Target profile formatter
│   │   ├── timeline.formatter.ts # Timeline formatter
│   │   └── network.formatter.ts  # Network mapping formatter
│   ├── exporters/
│   │   ├── pdf.exporter.ts      # PDF generation
│   │   ├── docx.exporter.ts     # Word document generation
│   │   ├── excel.exporter.ts    # Excel spreadsheet generation
│   │   ├── html.exporter.ts     # HTML generation
│   │   └── json.exporter.ts     # JSON export
│   └── templates/
│       └── default.template.md  # Default template
├── package.json
├── tsconfig.json
├── Dockerfile
└── README.md
```

## Development

### Setup

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev

# Build for production
npm run build

# Run tests
npm test
```

### Docker

```bash
# Build image
docker build -t apollo-reporting-service .

# Run container
docker run -p 3008:3008 -e NODE_ENV=production apollo-reporting-service
```

## Usage Examples

### Generate Investigation Summary PDF

```bash
curl -X POST http://localhost:3008/api/v1/reports/generate \
  -H "Content-Type: application/json" \
  -d '{
    "type": "investigation_summary",
    "format": "pdf",
    "parameters": {
      "investigationId": "inv-2024-001"
    },
    "options": {
      "classification": "SECRET",
      "includeTableOfContents": true
    }
  }'
```

### Generate Target Profile DOCX

```bash
curl -X POST http://localhost:3008/api/v1/reports/generate \
  -H "Content-Type: application/json" \
  -d '{
    "type": "target_profile",
    "format": "docx",
    "parameters": {
      "targetId": "tgt-hvt-001"
    },
    "options": {
      "classification": "TOP SECRET",
      "includeFinancials": true,
      "includeDigitalFootprint": true
    }
  }'
```

### Download Generated Report

```bash
# Get report status
curl http://localhost:3008/api/v1/reports/rpt-123-456

# Download when completed
curl -O http://localhost:3008/api/v1/reports/rpt-123-456/download
```

## Classification Handling

The service automatically adds classification banners, handling instructions, and watermarks based on the specified classification level:

- **TOP SECRET//SCI** - Yellow banner, SCI channel handling required
- **TOP SECRET** - Orange banner, secure channels only
- **SECRET** - Red banner, may cause serious damage warning
- **CONFIDENTIAL** - Blue banner, protect from disclosure
- **RESTRICTED** - Green banner, limited distribution
- **UNCLASSIFIED** - Green banner, no special handling
- **UNCLASSIFIED//FOUO** - Gray banner, exempt from public release

## Dependencies

- **PDFKit** - PDF generation
- **docx** - Word document generation
- **ExcelJS** - Excel spreadsheet generation
- **Puppeteer** - PDF rendering for complex layouts (optional)
- **Express** - HTTP server

## License

Proprietary - Apollo Intelligence Platform
