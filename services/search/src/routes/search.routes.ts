import { Router } from 'express';
import { searchService } from '../services/search.service';
import { createSuccessResponse } from '@apollo/shared';

const router = Router();

router.post('/', async (req, res, next) => {
  try {
    const { query, indices = ['investigations', 'targets', 'intelligence'], filters } = req.body;
    const results = await searchService.search(indices, query, filters);
    res.json(createSuccessResponse(results));
  } catch (error) {
    next(error);
  }
});

router.post('/index', async (req, res, next) => {
  try {
    const { index, id, document } = req.body;
    await searchService.indexDocument(index, id, document);
    res.json(createSuccessResponse({ message: 'Document indexed successfully' }));
  } catch (error) {
    next(error);
  }
});

router.get('/suggest', async (req, res, next) => {
  try {
    const { index, field, prefix } = req.query;
    const suggestions = await searchService.suggest(index as string, field as string, prefix as string);
    res.json(createSuccessResponse(suggestions));
  } catch (error) {
    next(error);
  }
});

router.delete('/:index/:id', async (req, res, next) => {
  try {
    await searchService.deleteDocument(req.params.index, req.params.id);
    res.json(createSuccessResponse({ message: 'Document deleted successfully' }));
  } catch (error) {
    next(error);
  }
});

export default router;
