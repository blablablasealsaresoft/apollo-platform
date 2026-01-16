/**
 * Task Relation Manager
 *
 * Manages complex task dependencies, parallel execution, and failure recovery.
 * Provides intelligent orchestration of multi-step operations.
 *
 * @module core/task-relation-manager
 */

import type { Task, SubTask } from './task-orchestrator';
import { ModelRouter } from '../ai-models/model-router';

export interface TaskGraph {
  nodes: TaskNode[];
  edges: TaskEdge[];
}

export interface TaskNode {
  id: string;
  task: SubTask;
  depth: number;
  parallelGroup?: number;
}

export interface TaskEdge {
  from: string;
  to: string;
  type: 'DEPENDENCY' | 'DATA_FLOW' | 'CONDITIONAL';
}

export interface ExecutionPlan {
  phases: ExecutionPhase[];
  parallelGroups: Map<number, string[]>;
  criticalPath: string[];
  estimatedDuration: number;
}

export interface ExecutionPhase {
  id: number;
  tasks: string[];
  canParallelize: boolean;
  dependencies: number[];
}

/**
 * Task Relation Manager
 *
 * Intelligently manages task relationships for optimal execution.
 */
export class TaskRelationManager {
  private modelRouter: ModelRouter;
  private taskGraphs: Map<string, TaskGraph>;

  constructor() {
    this.modelRouter = new ModelRouter();
    this.taskGraphs = new Map();
  }

  /**
   * Manage tasks with automatic orchestration
   */
  async manageTasks(rootTask: Task): Promise<any> {
    console.log(`[TaskRelation] Managing task: ${rootTask.id}`);

    // Build task graph
    const graph = this.buildTaskGraph(rootTask);
    this.taskGraphs.set(rootTask.id, graph);

    // Create execution plan
    const plan = await this.createExecutionPlan(graph);

    // Setup features
    const features = {
      dependencyTracking: this.trackDependencies(rootTask),
      failureRecovery: this.setupFailureRecovery(rootTask),
      parallelExecution: this.identifyParallelTasks(graph),
      contextPassing: this.setupContextFlow(rootTask),
      verification: this.setupVerification(rootTask)
    };

    console.log(`[TaskRelation] Execution plan created: ${plan.phases.length} phases`);
    console.log(`[TaskRelation] Parallel groups: ${plan.parallelGroups.size}`);

    return await this.execute(rootTask, features, plan);
  }

  /**
   * Build task dependency graph
   */
  private buildTaskGraph(task: Task): TaskGraph {
    const nodes: TaskNode[] = [];
    const edges: TaskEdge[] = [];

    // Create nodes for each subtask
    task.subtasks.forEach((subtask, index) => {
      nodes.push({
        id: subtask.id,
        task: subtask,
        depth: this.calculateDepth(subtask, task)
      });

      // Create edges for dependencies
      subtask.dependencies.forEach(depId => {
        edges.push({
          from: depId,
          to: subtask.id,
          type: 'DEPENDENCY'
        });
      });
    });

    return { nodes, edges };
  }

  /**
   * Calculate task depth in dependency tree
   */
  private calculateDepth(subtask: SubTask, task: Task): number {
    if (subtask.dependencies.length === 0) return 0;

    const depthsOfDependencies = subtask.dependencies.map(depId => {
      const dep = task.subtasks.find(st => st.id === depId);
      return dep ? this.calculateDepth(dep, task) + 1 : 0;
    });

    return Math.max(...depthsOfDependencies);
  }

  /**
   * Create optimized execution plan
   */
  private async createExecutionPlan(graph: TaskGraph): Promise<ExecutionPlan> {
    // Group tasks by depth (can execute in parallel)
    const depthGroups = new Map<number, TaskNode[]>();

    graph.nodes.forEach(node => {
      if (!depthGroups.has(node.depth)) {
        depthGroups.set(node.depth, []);
      }
      depthGroups.get(node.depth)!.push(node);
    });

    // Create execution phases
    const phases: ExecutionPhase[] = [];
    const parallelGroups = new Map<number, string[]>();

    Array.from(depthGroups.entries())
      .sort((a, b) => a[0] - b[0])
      .forEach(([depth, nodes]) => {
        phases.push({
          id: depth,
          tasks: nodes.map(n => n.id),
          canParallelize: nodes.length > 1,
          dependencies: depth > 0 ? [depth - 1] : []
        });

        if (nodes.length > 1) {
          parallelGroups.set(depth, nodes.map(n => n.id));
        }
      });

    // Identify critical path
    const criticalPath = this.findCriticalPath(graph);

    return {
      phases,
      parallelGroups,
      criticalPath,
      estimatedDuration: this.estimateDuration(phases)
    };
  }

  /**
   * Find critical path through task graph
   */
  private findCriticalPath(graph: TaskGraph): string[] {
    // Simple DFS to find longest path
    const longestPath: string[] = [];
    const visited = new Set<string>();

    const dfs = (nodeId: string, path: string[]) => {
      visited.add(nodeId);
      path.push(nodeId);

      const outgoingEdges = graph.edges.filter(e => e.from === nodeId);

      if (outgoingEdges.length === 0) {
        if (path.length > longestPath.length) {
          longestPath.length = 0;
          longestPath.push(...path);
        }
      } else {
        outgoingEdges.forEach(edge => {
          if (!visited.has(edge.to)) {
            dfs(edge.to, [...path]);
          }
        });
      }

      visited.delete(nodeId);
    };

    // Start from root nodes (no incoming edges)
    graph.nodes
      .filter(node => !graph.edges.some(e => e.to === node.id))
      .forEach(node => dfs(node.id, []));

    return longestPath;
  }

  /**
   * Estimate total execution duration
   */
  private estimateDuration(phases: ExecutionPhase[]): number {
    // Assuming average 5 minutes per phase
    // Parallel phases count as single phase
    return phases.length * 5;
  }

  /**
   * Track dependencies to ensure proper execution order
   */
  private trackDependencies(task: Task): any {
    return {
      ensureOrder: (subtask: SubTask) => {
        // Verify all dependencies completed before execution
        return task.subtasks
          .filter(st => subtask.dependencies.includes(st.id))
          .every(st => st.status === 'COMPLETED');
      }
    };
  }

  /**
   * Setup failure recovery with AI re-planning
   */
  private setupFailureRecovery(task: Task): any {
    return {
      onFailure: async (failedSubtask: SubTask) => {
        console.log(`[TaskRelation] Subtask failed: ${failedSubtask.id}`);
        console.log(`[TaskRelation] Initiating AI re-planning...`);

        const model = this.modelRouter.selectModel('medium');

        const prompt = `
A subtask has failed during execution:

Failed Task: ${failedSubtask.action}
Tools Used: ${failedSubtask.tools.join(', ')}
Remaining Objective: ${task.abstract}

Generate alternative approach:
1. Identify why it likely failed
2. Suggest alternative tools
3. Create new subtask plan
4. Maintain overall objective

Return JSON with new subtask definition.
        `;

        const alternativePlan = await model.generate(prompt);

        // Create new subtask with alternative approach
        const newSubtask: SubTask = {
          id: `${failedSubtask.id}-retry`,
          parentId: failedSubtask.parentId,
          action: `${failedSubtask.action} (alternative approach)`,
          tools: alternativePlan.tools || failedSubtask.tools,
          dependencies: failedSubtask.dependencies,
          status: 'PENDING'
        };

        return newSubtask;
      }
    };
  }

  /**
   * Identify tasks that can execute in parallel
   */
  private identifyParallelTasks(graph: TaskGraph): Map<number, string[]> {
    const parallelGroups = new Map<number, string[]>();

    // Group by depth - same depth can run in parallel
    graph.nodes.forEach(node => {
      if (!parallelGroups.has(node.depth)) {
        parallelGroups.set(node.depth, []);
      }
      parallelGroups.get(node.depth)!.push(node.id);
    });

    // Filter to only groups with multiple tasks
    Array.from(parallelGroups.entries()).forEach(([depth, tasks]) => {
      if (tasks.length <= 1) {
        parallelGroups.delete(depth);
      }
    });

    return parallelGroups;
  }

  /**
   * Setup context flow between tasks
   */
  private setupContextFlow(task: Task): any {
    const context = new Map<string, any>();

    return {
      storeResult: (subtaskId: string, result: any) => {
        context.set(subtaskId, result);
      },
      getResult: (subtaskId: string) => {
        return context.get(subtaskId);
      },
      getAllResults: () => {
        return Object.fromEntries(context);
      }
    };
  }

  /**
   * Setup verification of task completion
   */
  private setupVerification(task: Task): any {
    return {
      verify: async () => {
        // Verify all subtasks completed successfully
        const allCompleted = task.subtasks.every(st => st.status === 'COMPLETED');

        // Verify success criteria met
        const criteriaVerification = await this.verifyCriteria(task);

        return allCompleted && criteriaVerification;
      }
    };
  }

  /**
   * Verify task success criteria
   */
  private async verifyCriteria(task: Task): Promise<boolean> {
    const model = this.modelRouter.selectModel('medium');

    const prompt = `
Verify if task success criteria has been met:

Task: ${task.abstract}
Description: ${task.description}
Verification Criteria: ${task.verification}

Subtask Results:
${task.subtasks.map(st => `- ${st.action}: ${st.status}`).join('\n')}

Has the verification criteria been satisfied? Return JSON with:
- satisfied: boolean
- reasoning: string
    `;

    const verification = await model.generate(prompt);
    return verification.satisfied || false;
  }

  /**
   * Execute task with all orchestration features
   */
  private async execute(task: Task, features: any, plan: ExecutionPlan): Promise<any> {
    console.log(`[TaskRelation] Executing task with ${plan.phases.length} phases`);

    const results: any[] = [];

    // Execute phases in order
    for (const phase of plan.phases) {
      console.log(`[TaskRelation] Executing phase ${phase.id} (${phase.tasks.length} tasks)`);

      if (phase.canParallelize) {
        // Execute tasks in parallel
        const phaseResults = await Promise.all(
          phase.tasks.map(taskId => this.executeTaskNode(taskId, task, features))
        );
        results.push(...phaseResults);
      } else {
        // Execute tasks sequentially
        for (const taskId of phase.tasks) {
          const result = await this.executeTaskNode(taskId, task, features);
          results.push(result);
        }
      }
    }

    // Verify completion
    const verified = await features.verification.verify();

    return {
      success: verified,
      results,
      context: features.contextPassing.getAllResults()
    };
  }

  /**
   * Execute individual task node
   */
  private async executeTaskNode(taskId: string, task: Task, features: any): Promise<any> {
    const subtask = task.subtasks.find(st => st.id === taskId);
    if (!subtask) return { success: false, error: 'Task not found' };

    // Check dependencies
    const depsReady = features.dependencyTracking.ensureOrder(subtask);
    if (!depsReady) {
      return { success: false, error: 'Dependencies not met' };
    }

    // Execute (simplified - would use TaskOrchestrator)
    try {
      const result = { success: true, data: {} };

      // Store result in context
      features.contextPassing.storeResult(taskId, result);

      return result;
    } catch (error) {
      // Failure recovery
      const alternative = await features.failureRecovery.onFailure(subtask);
      return { success: false, alternative };
    }
  }

  /**
   * Get task graph visualization
   */
  getTaskGraph(taskId: string): TaskGraph | undefined {
    return this.taskGraphs.get(taskId);
  }
}

export default TaskRelationManager;
