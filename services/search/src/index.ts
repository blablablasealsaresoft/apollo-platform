import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config, logger } from '@apollo/shared';
import searchRoutes from './routes/search.routes';
import { searchService } from './services/search.service';

const app = express();
const PORT = process.env.SEARCH_SERVICE_PORT || 3007;

app.use(helmet());
app.use(cors({ origin: config.cors.origin }));
app.use(express.json());

app.get('/health', async (req, res) => {
  const healthy = await searchService.healthCheck();
  res.status(healthy ? 200 : 503).json({ status: healthy ? 'healthy' : 'unhealthy', service: 'search' });
});

app.use('/api/search', searchRoutes);

const startServer = async () => {
  await searchService.initialize();
  app.listen(PORT, () => logger.info(`Search service on port ${PORT}`));
};

startServer();
export default app;
