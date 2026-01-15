import {
  database,
  logger,
  generateId,
  NotFoundError,
  ConflictError,
  User,
  UserRole,
  ClearanceLevel,
  PaginationParams,
  PaginatedResponse,
} from '@apollo/shared';

export class UserService {
  async getAllUsers(params: PaginationParams): Promise<PaginatedResponse<User>> {
    const { page = 1, limit = 20, sortBy = 'created_at', sortOrder = 'desc' } = params;
    const offset = (page - 1) * limit;

    const countResult = await database.query('SELECT COUNT(*) FROM users');
    const total = parseInt(countResult.rows[0]!.count);

    const result = await database.query<User>(
      `SELECT
        id, email, username, first_name as "firstName", last_name as "lastName",
        role, clearance_level as "clearanceLevel",
        is_active as "isActive", is_mfa_enabled as "isMfaEnabled",
        last_login as "lastLogin", created_at as "createdAt", updated_at as "updatedAt"
      FROM users
      ORDER BY ${sortBy} ${sortOrder}
      LIMIT $1 OFFSET $2`,
      [limit, offset],
    );

    return {
      items: result.rows,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  async getUserById(id: string): Promise<User> {
    const result = await database.query<User>(
      `SELECT
        id, email, username, first_name as "firstName", last_name as "lastName",
        role, clearance_level as "clearanceLevel",
        is_active as "isActive", is_mfa_enabled as "isMfaEnabled",
        last_login as "lastLogin", created_at as "createdAt", updated_at as "updatedAt"
      FROM users WHERE id = $1`,
      [id],
    );

    if (result.rows.length === 0) {
      throw new NotFoundError('User not found');
    }

    return result.rows[0]!;
  }

  async updateUser(
    id: string,
    updates: Partial<{
      firstName: string;
      lastName: string;
      role: UserRole;
      clearanceLevel: ClearanceLevel;
      isActive: boolean;
    }>,
  ): Promise<User> {
    const user = await this.getUserById(id);

    const updateFields: string[] = [];
    const values: any[] = [];
    let paramIndex = 1;

    if (updates.firstName !== undefined) {
      updateFields.push(`first_name = $${paramIndex++}`);
      values.push(updates.firstName);
    }
    if (updates.lastName !== undefined) {
      updateFields.push(`last_name = $${paramIndex++}`);
      values.push(updates.lastName);
    }
    if (updates.role !== undefined) {
      updateFields.push(`role = $${paramIndex++}`);
      values.push(updates.role);
    }
    if (updates.clearanceLevel !== undefined) {
      updateFields.push(`clearance_level = $${paramIndex++}`);
      values.push(updates.clearanceLevel);
    }
    if (updates.isActive !== undefined) {
      updateFields.push(`is_active = $${paramIndex++}`);
      values.push(updates.isActive);
    }

    if (updateFields.length === 0) {
      return user;
    }

    updateFields.push('updated_at = NOW()');
    values.push(id);

    const result = await database.query<User>(
      `UPDATE users
       SET ${updateFields.join(', ')}
       WHERE id = $${paramIndex}
       RETURNING id, email, username, first_name as "firstName", last_name as "lastName",
                 role, clearance_level as "clearanceLevel",
                 is_active as "isActive", is_mfa_enabled as "isMfaEnabled",
                 last_login as "lastLogin", created_at as "createdAt", updated_at as "updatedAt"`,
      values,
    );

    logger.info(`User updated: ${id}`);
    return result.rows[0]!;
  }

  async deleteUser(id: string): Promise<void> {
    const result = await database.query('DELETE FROM users WHERE id = $1', [id]);

    if (result.rowCount === 0) {
      throw new NotFoundError('User not found');
    }

    logger.info(`User deleted: ${id}`);
  }

  async searchUsers(query: string): Promise<User[]> {
    const result = await database.query<User>(
      `SELECT
        id, email, username, first_name as "firstName", last_name as "lastName",
        role, clearance_level as "clearanceLevel",
        is_active as "isActive", is_mfa_enabled as "isMfaEnabled",
        last_login as "lastLogin", created_at as "createdAt", updated_at as "updatedAt"
      FROM users
      WHERE email ILIKE $1 OR username ILIKE $1 OR first_name ILIKE $1 OR last_name ILIKE $1
      LIMIT 50`,
      [`%${query}%`],
    );

    return result.rows;
  }

  async getUserActivity(userId: string, limit: number = 50): Promise<any[]> {
    const result = await database.query(
      `SELECT
        id, action, resource_type as "resourceType", resource_id as "resourceId",
        metadata, ip_address as "ipAddress", user_agent as "userAgent", timestamp
      FROM activity_logs
      WHERE user_id = $1
      ORDER BY timestamp DESC
      LIMIT $2`,
      [userId, limit],
    );

    return result.rows;
  }
}

export const userService = new UserService();
