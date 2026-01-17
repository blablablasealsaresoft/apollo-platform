import { Router } from 'express';
import { operationService, OperationType, OperationStatusType, OperationPriorityType } from '../services/operation.service';
import { createSuccessResponse } from '@apollo/shared';

const router = Router();

// Create a new operation
router.post('/', async (req, res, next) => {
  try {
    const {
      investigationId,
      operationName,
      operationType,
      objective,
      createdBy,
      targetId,
      operationNumber,
      priority,
      strategy,
      plannedDate,
      operationLead,
      operationLocation,
      classificationLevel,
    } = req.body;

    const operation = await operationService.createOperation({
      investigationId,
      operationName,
      operationType,
      objective,
      createdBy,
      targetId,
      operationNumber,
      priority,
      strategy,
      plannedDate: plannedDate ? new Date(plannedDate) : undefined,
      operationLead,
      operationLocation,
      classificationLevel,
    });
    res.status(201).json(createSuccessResponse(operation));
  } catch (error) {
    next(error);
  }
});

// List operations with optional filters
router.get('/', async (req, res, next) => {
  try {
    const { status, priority, investigationId, operationType, limit, offset } = req.query;
    const operations = await operationService.listOperations({
      status: status as OperationStatusType | undefined,
      priority: priority as OperationPriorityType | undefined,
      investigationId: investigationId as string | undefined,
      operationType: operationType as OperationType | undefined,
      limit: limit ? parseInt(limit as string, 10) : undefined,
      offset: offset ? parseInt(offset as string, 10) : undefined,
    });
    res.json(createSuccessResponse(operations));
  } catch (error) {
    next(error);
  }
});

// Get operations by investigation ID
router.get('/investigation/:investigationId', async (req, res, next) => {
  try {
    const { limit, offset } = req.query;
    const result = await operationService.getOperationsByInvestigation(
      req.params.investigationId,
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

// Get a specific operation by ID
router.get('/:id', async (req, res, next) => {
  try {
    const operation = await operationService.getOperationById(req.params.id);
    res.json(createSuccessResponse(operation));
  } catch (error) {
    next(error);
  }
});

// Update an operation
router.patch('/:id', async (req, res, next) => {
  try {
    const operation = await operationService.updateOperation(req.params.id, req.body);
    res.json(createSuccessResponse(operation));
  } catch (error) {
    next(error);
  }
});

// Update operation status
router.patch('/:id/status', async (req, res, next) => {
  try {
    const { status, updatedBy } = req.body;
    const operation = await operationService.updateOperationStatus(req.params.id, status, updatedBy);
    res.json(createSuccessResponse(operation));
  } catch (error) {
    next(error);
  }
});

// Delete an operation
router.delete('/:id', async (req, res, next) => {
  try {
    await operationService.deleteOperation(req.params.id);
    res.json(createSuccessResponse({ message: 'Operation deleted' }));
  } catch (error) {
    next(error);
  }
});

// Get team members for an operation
router.get('/:id/team', async (req, res, next) => {
  try {
    const teamMembers = await operationService.getTeamMembers(req.params.id);
    res.json(createSuccessResponse({ teamMembers }));
  } catch (error) {
    next(error);
  }
});

// Assign a team member to an operation
router.post('/:id/team/:userId', async (req, res, next) => {
  try {
    await operationService.assignTeamMember(req.params.id, req.params.userId);
    res.json(createSuccessResponse({ message: 'Team member assigned' }));
  } catch (error) {
    next(error);
  }
});

// Remove a team member from an operation
router.delete('/:id/team/:userId', async (req, res, next) => {
  try {
    await operationService.removeTeamMember(req.params.id, req.params.userId);
    res.json(createSuccessResponse({ message: 'Team member removed' }));
  } catch (error) {
    next(error);
  }
});

export default router;
