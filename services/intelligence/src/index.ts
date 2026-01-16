import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config, logger, database } from '@apollo/shared';
import intelRoutes from './routes/intel.routes';
import correlationRoutes from './routes/correlation.routes';

const app = express();
const PORT = process.env.INTELLIGENCE_SERVICE_PORT || 3004;

app.use(helmet());
app.use(cors({ origin: config.cors.origin }));
app.use(express.json());

app.get('/health', async (req, res) => {
  const healthy = await database.healthCheck();
  res.status(healthy ? 200 : 503).json({ status: healthy ? 'healthy' : 'unhealthy', service: 'intelligence' });
});

app.use('/api/intelligence', intelRoutes);
app.use('/api/correlation', correlationRoutes);

app.listen(PORT, () => logger.info(`Intelligence service on port ${PORT}`));
export default app;
