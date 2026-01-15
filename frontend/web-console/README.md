# Apollo Platform - Web Console

Elite-level React/TypeScript web application for criminal investigation management.

## Features

### Core Modules
- **Dashboard**: Real-time overview with stats, alerts, and activity feed
- **Investigations**: Complete case management with timeline and team collaboration
- **Targets**: Comprehensive target profiles with network visualization
- **Evidence**: Chain of custody tracking and file management
- **Intelligence**: Intelligence reports with correlation analysis
- **Operations**: Field operations planning and execution tracking
- **Blockchain**: Cryptocurrency wallet monitoring and transaction tracking
- **Facial Recognition**: Image-based facial matching and live feed monitoring
- **Analytics**: Custom reports and data visualization
- **Settings & Admin**: User management, system configuration, and audit logs

### Technical Stack
- **React 18.2** with TypeScript (strict mode)
- **Vite** for blazing-fast builds and HMR
- **TailwindCSS** for utility-first styling
- **Redux Toolkit** for state management with Redux Persist
- **React Router v6** for client-side routing
- **React Query** for server state management
- **Axios** with interceptors for API communication
- **Socket.io Client** for real-time WebSocket updates
- **Formik + Yup** for form handling and validation
- **Chart.js & D3.js** for data visualizations
- **Leaflet** for map visualizations
- **date-fns** for date formatting
- **React Hot Toast** for notifications

## Project Structure

```
src/
├── components/
│   ├── common/
│   │   ├── Layout/
│   │   │   └── MainLayout.tsx      # Main application layout
│   │   ├── Forms/                   # Reusable form components
│   │   ├── UI/                      # Common UI components
│   │   └── ProtectedRoute.tsx       # Route protection
│   ├── analytics/                   # Analytics-specific components
│   ├── intelligence/                # Intelligence module components
│   ├── investigation/               # Investigation components
│   └── operations/                  # Operations components
├── pages/
│   ├── Auth/
│   │   ├── LoginPage.tsx
│   │   └── RegisterPage.tsx
│   ├── Dashboard/
│   │   └── DashboardPage.tsx
│   ├── Investigations/
│   │   ├── InvestigationsListPage.tsx
│   │   └── InvestigationDetailPage.tsx
│   ├── Targets/
│   │   ├── TargetsListPage.tsx
│   │   └── TargetDetailPage.tsx
│   ├── Evidence/
│   ├── Intelligence/
│   ├── Operations/
│   ├── Blockchain/
│   ├── FacialRecognition/
│   ├── Analytics/
│   ├── Settings/
│   └── Administration/
├── services/
│   ├── api/
│   │   ├── client.ts               # Axios client with interceptors
│   │   ├── auth.service.ts
│   │   ├── investigations.service.ts
│   │   ├── targets.service.ts
│   │   ├── evidence.service.ts
│   │   ├── intelligence.service.ts
│   │   ├── operations.service.ts
│   │   ├── blockchain.service.ts
│   │   ├── facial.service.ts
│   │   ├── dashboard.service.ts
│   │   └── admin.service.ts
│   └── websocket/
│       └── client.ts               # WebSocket client
├── store/
│   ├── slices/
│   │   ├── authSlice.ts
│   │   ├── investigationsSlice.ts
│   │   ├── targetsSlice.ts
│   │   ├── evidenceSlice.ts
│   │   ├── alertsSlice.ts
│   │   └── operationsSlice.ts
│   ├── hooks.ts                    # Typed Redux hooks
│   └── index.ts                    # Store configuration
├── hooks/
│   └── useWebSocket.ts             # Custom WebSocket hook
├── types/
│   └── index.ts                    # TypeScript type definitions
├── utils/
│   ├── cn.ts                       # className utility
│   └── formatters.ts               # Date/number formatters
├── styles/
│   └── index.css                   # Global styles with Tailwind
├── App.tsx                         # Root component with routing
└── main.tsx                        # Application entry point
```

## Getting Started

### Prerequisites
- Node.js 18.x or higher
- npm 9.x or higher

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd apollo/frontend/web-console
```

2. **Install dependencies**
```bash
npm install
```

3. **Set up environment variables**
```bash
cp .env.example .env
```

Edit `.env` and configure:
```env
VITE_API_BASE_URL=http://localhost:8000/api
VITE_WS_URL=ws://localhost:8000
```

4. **Start development server**
```bash
npm run dev
```

The application will be available at `http://localhost:3000`

### Development Scripts

```bash
# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview

# Run linter
npm run lint

# Format code
npm run format

# Type check
npm run type-check

# Run tests
npm test

# Run tests with UI
npm run test:ui

# E2E tests (Cypress)
npm run test:e2e
npm run test:e2e:headless
```

## Docker Deployment

### Build Docker image
```bash
docker build -t apollo-web-console .
```

### Run container
```bash
docker run -p 80:80 apollo-web-console
```

### Docker Compose (with backend)
```yaml
version: '3.8'
services:
  web:
    build: .
    ports:
      - "80:80"
    environment:
      - VITE_API_BASE_URL=http://backend:8000/api
    depends_on:
      - backend
```

## Configuration

### API Client
The API client (`src/services/api/client.ts`) includes:
- JWT token authentication
- Automatic token refresh
- Request/response interceptors
- Error handling
- Retry logic

### WebSocket
Real-time updates via Socket.io:
- Automatic reconnection
- Event subscription management
- Entity-specific subscriptions

### State Management
Redux Toolkit with:
- Auth state persistence
- Async thunk actions
- Normalized state structure
- Real-time state updates via WebSocket

## Features Implementation

### Authentication
- Login/Register with JWT
- MFA support (TOTP)
- Password reset flow
- Session management
- Auto token refresh

### Real-time Updates
WebSocket integration for:
- New alerts
- Investigation updates
- Target changes
- Operation status changes
- Facial recognition matches
- Blockchain transaction alerts

### Security
- Protected routes
- Role-based access control
- Secure token storage
- XSS protection
- CSRF protection
- Content Security Policy

### Performance
- Code splitting
- Lazy loading routes
- Image optimization
- Virtualized lists
- Memoization
- Query caching with React Query

### Accessibility
- WCAG 2.1 AA compliant
- Keyboard navigation
- Screen reader support
- Focus management
- ARIA labels

## API Integration

All API services are located in `src/services/api/`:

```typescript
// Example: Fetch investigations
import { investigationsService } from '@services/api';

const investigations = await investigationsService.getAll();
```

### Available Services
- `authService` - Authentication and user management
- `investigationsService` - Investigation CRUD operations
- `targetsService` - Target management
- `evidenceService` - Evidence handling
- `intelligenceService` - Intelligence reports
- `operationsService` - Operations management
- `blockchainService` - Blockchain tracking
- `facialService` - Facial recognition
- `dashboardService` - Dashboard data
- `adminService` - Administration

## Styling

### TailwindCSS Utilities
The project uses custom Tailwind utilities:

```jsx
// Buttons
<button className="btn-primary">Primary</button>
<button className="btn-secondary">Secondary</button>
<button className="btn-danger">Danger</button>

// Cards
<div className="card">Content</div>

// Badges
<span className="badge badge-primary">Badge</span>

// Inputs
<input className="input" />
```

### Dark Mode
Dark mode support via Tailwind's dark mode:
```jsx
<div className="bg-white dark:bg-dark-800">
  Content
</div>
```

## Testing

### Unit Tests (Vitest)
```bash
npm test
```

### E2E Tests (Cypress)
```bash
npm run test:e2e
```

## Browser Support
- Chrome/Edge (latest 2 versions)
- Firefox (latest 2 versions)
- Safari (latest 2 versions)

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VITE_API_BASE_URL` | Backend API URL | `http://localhost:8000/api` |
| `VITE_WS_URL` | WebSocket URL | `ws://localhost:8000` |
| `VITE_ENV` | Environment | `development` |

## Troubleshooting

### Port already in use
```bash
# Kill process on port 3000
npx kill-port 3000
```

### Build errors
```bash
# Clear cache and reinstall
rm -rf node_modules package-lock.json
npm install
```

### Type errors
```bash
# Run type check
npm run type-check
```

## Contributing

1. Create a feature branch
2. Make changes
3. Run linter and tests
4. Submit pull request

## License

Classified - Authorized Personnel Only

## Support

For support and questions, contact the Apollo Platform development team.

---

**Apollo Platform** - Elite Criminal Investigation System
Version 1.0.0
