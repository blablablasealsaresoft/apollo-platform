import { Router } from 'express';
import { userService } from '../services/user.service';
import { authenticate, authorize } from '../middleware/auth.middleware';
import { createSuccessResponse, UserRole } from '@apollo/shared';

const router = Router();

router.use(authenticate);

// Get all users
router.get('/', authorize(UserRole.ADMIN, UserRole.INVESTIGATOR), async (req, res, next) => {
  try {
    const { page = 1, limit = 20, sortBy, sortOrder } = req.query;
    const users = await userService.getAllUsers({
      page: Number(page),
      limit: Number(limit),
      sortBy: sortBy as string,
      sortOrder: sortOrder as 'asc' | 'desc',
    });
    res.json(createSuccessResponse(users));
  } catch (error) {
    next(error);
  }
});

// Search users
router.get('/search', async (req, res, next) => {
  try {
    const { q } = req.query;
    const users = await userService.searchUsers(q as string);
    res.json(createSuccessResponse(users));
  } catch (error) {
    next(error);
  }
});

// Get user by ID
router.get('/:id', async (req, res, next) => {
  try {
    const user = await userService.getUserById(req.params.id);
    res.json(createSuccessResponse(user));
  } catch (error) {
    next(error);
  }
});

// Update user
router.patch('/:id', authorize(UserRole.ADMIN), async (req, res, next) => {
  try {
    const user = await userService.updateUser(req.params.id, req.body);
    res.json(createSuccessResponse(user));
  } catch (error) {
    next(error);
  }
});

// Delete user
router.delete('/:id', authorize(UserRole.ADMIN), async (req, res, next) => {
  try {
    await userService.deleteUser(req.params.id);
    res.json(createSuccessResponse({ message: 'User deleted successfully' }));
  } catch (error) {
    next(error);
  }
});

// Get user activity
router.get('/:id/activity', async (req, res, next) => {
  try {
    const { limit = 50 } = req.query;
    const activity = await userService.getUserActivity(req.params.id, Number(limit));
    res.json(createSuccessResponse(activity));
  } catch (error) {
    next(error);
  }
});

export default router;
