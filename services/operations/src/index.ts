import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config, logger, database } from '@apollo/shared';
import operationRoutes from './routes/operation.routes';
import fieldReportRoutes from './routes/field-report.routes';
import { errorHandler } from './middleware/error.middleware';

const app = express();
const PORT = process.env.OPERATIONS_SERVICE_PORT || 3003;

app.use(helmet());
app.use(cors({ origin: config.cors.origin }));
app.use(express.json());

app.get('/health', async (req, res) => {
  const dbHealthy = await database.healthCheck();
  res.status(dbHealthy ? 200 : 503).json({ status: dbHealthy ? 'healthy' : 'unhealthy', service: 'operations' });
});

app.use('/api/operations', operationRoutes);
app.use('/api/field-reports', fieldReportRoutes);
app.use(errorHandler);

app.listen(PORT, () => logger.info(`Operations service on port ${PORT}`));
export default app;
