import { Router } from 'express';
import { operationService } from '../services/operation.service';
import { createSuccessResponse } from '@apollo/shared';

const router = Router();

router.post('/', async (req, res, next) => {
  try {
    const operation = await operationService.createOperation(req.body);
    res.status(201).json(createSuccessResponse(operation));
  } catch (error) {
    next(error);
  }
});

router.get('/', async (req, res, next) => {
  try {
    const operations = await operationService.listOperations(req.query as any);
    res.json(createSuccessResponse(operations));
  } catch (error) {
    next(error);
  }
});

router.get('/:id', async (req, res, next) => {
  try {
    const operation = await operationService.getOperationById(req.params.id);
    res.json(createSuccessResponse(operation));
  } catch (error) {
    next(error);
  }
});

router.patch('/:id', async (req, res, next) => {
  try {
    const operation = await operationService.updateOperation(req.params.id, req.body);
    res.json(createSuccessResponse(operation));
  } catch (error) {
    next(error);
  }
});

router.delete('/:id', async (req, res, next) => {
  try {
    await operationService.deleteOperation(req.params.id);
    res.json(createSuccessResponse({ message: 'Operation deleted' }));
  } catch (error) {
    next(error);
  }
});

router.post('/:id/team/:userId', async (req, res, next) => {
  try {
    await operationService.assignTeamMember(req.params.id, req.params.userId);
    res.json(createSuccessResponse({ message: 'Team member assigned' }));
  } catch (error) {
    next(error);
  }
});

router.delete('/:id/team/:userId', async (req, res, next) => {
  try {
    await operationService.removeTeamMember(req.params.id, req.params.userId);
    res.json(createSuccessResponse({ message: 'Team member removed' }));
  } catch (error) {
    next(error);
  }
});

export default router;
