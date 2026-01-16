import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config, logger, database } from '@apollo/shared';
import analyticsRoutes from './routes/analytics.routes';

const app = express();
const PORT = process.env.ANALYTICS_SERVICE_PORT || 3006;

app.use(helmet());
app.use(cors({ origin: config.cors.origin }));
app.use(express.json());

app.get('/health', async (req, res) => {
  const healthy = await database.healthCheck();
  res.status(healthy ? 200 : 503).json({ status: healthy ? 'healthy' : 'unhealthy', service: 'analytics' });
});

app.use('/api/analytics', analyticsRoutes);

app.listen(PORT, () => logger.info(`Analytics service on port ${PORT}`));
export default app;
