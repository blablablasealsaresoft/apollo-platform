import { Router } from 'express';
import { createSuccessResponse } from '@apollo/shared';
import { fieldReportService } from '../services/field-report.service';

const router = Router();

// Create a new field report
router.post('/', async (req, res, next) => {
  try {
    const { operationId, title, content, createdBy, summary, reportType, location } = req.body;
    const report = await fieldReportService.createFieldReport({
      operationId,
      title,
      content,
      createdBy,
      summary,
      reportType,
      location,
    });
    res.status(201).json(createSuccessResponse(report));
  } catch (error) {
    next(error);
  }
});

// List all field reports for an operation
router.get('/operation/:operationId', async (req, res, next) => {
  try {
    const { limit, offset } = req.query;
    const result = await fieldReportService.listByOperationId(
      req.params.operationId,
      {
        limit: limit ? parseInt(limit as string, 10) : undefined,
        offset: offset ? parseInt(offset as string, 10) : undefined,
      }
    );
    res.json(createSuccessResponse(result));
  } catch (error) {
    next(error);
  }
});

// Get a specific field report by ID
router.get('/:id', async (req, res, next) => {
  try {
    const report = await fieldReportService.getFieldReportById(req.params.id);
    res.json(createSuccessResponse(report));
  } catch (error) {
    next(error);
  }
});

// Update a field report
router.patch('/:id', async (req, res, next) => {
  try {
    const report = await fieldReportService.updateFieldReport(req.params.id, req.body);
    res.json(createSuccessResponse(report));
  } catch (error) {
    next(error);
  }
});

// Delete a field report
router.delete('/:id', async (req, res, next) => {
  try {
    await fieldReportService.deleteFieldReport(req.params.id);
    res.json(createSuccessResponse({ message: 'Field report deleted' }));
  } catch (error) {
    next(error);
  }
});

export default router;
