import { v4 as uuidv4 } from 'uuid'; // For generating unique IDs

import { Message, AgentCard, PushNotificationConfig, Task, MessageSendParams, TaskState, TaskStatusUpdateEvent, TaskArtifactUpdateEvent, TaskQueryParams, TaskIdParams, TaskPushNotificationConfig } from "../../types.js";
import { AgentExecutor } from "../agent_execution/agent_executor.js";
import { RequestContext } from "../agent_execution/request_context.js";
import { A2AError } from "../error.js";
import { ExecutionEventBusManager, DefaultExecutionEventBusManager } from "../events/execution_event_bus_manager.js";
import { ExecutionEventBus } from "../events/execution_event_bus.js";
import { ExecutionEventQueue } from "../events/execution_event_queue.js";
import { ResultManager } from "../result_manager.js";
import { TaskStore } from "../store.js";
import { A2ARequestHandler } from "./a2a_request_handler.js";

const terminalStates: TaskState[] = ["completed", "failed", "canceled", "rejected"];

export class DefaultRequestHandler implements A2ARequestHandler {
    private readonly agentCard: AgentCard;
    private readonly taskStore: TaskStore;
    private readonly agentExecutor: AgentExecutor;
    private readonly eventBusManager: ExecutionEventBusManager;
    // Store for push notification configurations (could be part of TaskStore or separate)
    private readonly pushNotificationConfigs: Map<string, PushNotificationConfig> = new Map();


    constructor(
        agentCard: AgentCard,
        taskStore: TaskStore,
        agentExecutor: AgentExecutor,
        eventBusManager: ExecutionEventBusManager = new DefaultExecutionEventBusManager(),
    ) {
        this.agentCard = agentCard;
        this.taskStore = taskStore;
        this.agentExecutor = agentExecutor;
        this.eventBusManager = eventBusManager;
    }

    async getAgentCard(): Promise<AgentCard> {
        return this.agentCard;
    }

    private async _createRequestContext(
        incomingMessage: Message,
        taskId: string,
        isStream: boolean,
    ): Promise<RequestContext> {
        let task: Task | undefined;
        let referenceTasks: Task[] | undefined;

        // incomingMessage would contain taskId, if a task already exists.
        if (incomingMessage.taskId) {
            task = await this.taskStore.load(incomingMessage.taskId);
            if (!task) {
                throw A2AError.taskNotFound(incomingMessage.taskId);
            }
            
            if (terminalStates.includes(task.status.state)) {
                // Throw an error that conforms to the JSON-RPC Invalid Request error specification.
                throw A2AError.invalidRequest(`Task ${task.id} is in a terminal state (${task.status.state}) and cannot be modified.`)
            }
        }

        if (incomingMessage.referenceTaskIds && incomingMessage.referenceTaskIds.length > 0) {
            referenceTasks = [];
            for (const refId of incomingMessage.referenceTaskIds) {
                const refTask = await this.taskStore.load(refId);
                if (refTask) {
                    referenceTasks.push(refTask);
                } else {
                    console.warn(`Reference task ${refId} not found.`);
                    // Optionally, throw an error or handle as per specific requirements
                }
            }
        }

        // Ensure contextId is present
        const contextId = incomingMessage.contextId || task?.contextId || uuidv4();

        const messageForContext = {
          ...incomingMessage,
          contextId,
        };

        return new RequestContext(
            messageForContext,
            taskId,
            contextId,
            task,
            referenceTasks
        );
    }

    private async _processEvents(
        taskId: string,
        resultManager: ResultManager,
        eventQueue: ExecutionEventQueue,
        options?: {
            firstResultResolver?: (value: Message | Task | PromiseLike<Message | Task>) => void;
            firstResultRejector?: (reason?: any) => void;
        }
    ): Promise<void> {
        let firstResultSent = false;
        try {
            for await (const event of eventQueue.events()) {
                await resultManager.processEvent(event);

                if (options?.firstResultResolver && !firstResultSent) {
                    if (event.kind === 'message' || event.kind === 'task') {
                        options.firstResultResolver(event as Message | Task);
                        firstResultSent = true;
                    }
                }
            }
            if (options?.firstResultRejector && !firstResultSent) {
                options.firstResultRejector(A2AError.internalError('Execution finished before a message or task was produced.'));
            }
        } catch (error) {
            console.error(`Event processing loop failed for task ${taskId}:`, error);
            if (options?.firstResultRejector && !firstResultSent) {
                options.firstResultRejector(error);
            }
            // re-throw error for blocking case to catch
            throw error;
        } finally {
            this.eventBusManager.cleanupByTaskId(taskId);
        }
    }

    async sendMessage(
        params: MessageSendParams
    ): Promise<Message | Task> {
        const incomingMessage = params.message;
        if (!incomingMessage.messageId) {
            throw A2AError.invalidParams('message.messageId is required.');
        }

        // Default to blocking behavior if 'blocking' is not explicitly false.
        const isBlocking = params.configuration?.blocking !== false;
        const taskId = incomingMessage.taskId || uuidv4();

        // Instantiate ResultManager before creating RequestContext
        const resultManager = new ResultManager(this.taskStore);
        resultManager.setContext(incomingMessage); // Set context for ResultManager

        const requestContext = await this._createRequestContext(incomingMessage, taskId, false);
        // Use the (potentially updated) contextId from requestContext
        const finalMessageForAgent = requestContext.userMessage;


        const eventBus = this.eventBusManager.createOrGetByTaskId(taskId);
        // EventQueue should be attached to the bus, before the agent execution begins.
        const eventQueue = new ExecutionEventQueue(eventBus);
        
        // Start agent execution (non-blocking).
        // It runs in the background and publishes events to the eventBus.
        this.agentExecutor.execute(requestContext, eventBus).catch(err => {
            console.error(`Agent execution failed for message ${finalMessageForAgent.messageId}:`, err);
            // Publish a synthetic error event, which will be handled by the ResultManager
            // and will also settle the firstResultPromise for non-blocking calls.
            const errorTask: Task = {
                id: requestContext.task?.id || uuidv4(), // Use existing task ID or generate new
                contextId: finalMessageForAgent.contextId!,
                status: {
                    state: "failed",
                    message: {
                        kind: "message",
                        role: "agent",
                        messageId: uuidv4(),
                        parts: [{ kind: "text", text: `Agent execution error: ${err.message}` }],
                        taskId: requestContext.task?.id,
                        contextId: finalMessageForAgent.contextId!,
                    },
                    timestamp: new Date().toISOString(),
                },
                history: requestContext.task?.history ? [...requestContext.task.history] : [],
                kind: "task",
            };
            if (finalMessageForAgent) { // Add incoming message to history
                if (!errorTask.history?.find(m => m.messageId === finalMessageForAgent.messageId)) {
                    errorTask.history?.push(finalMessageForAgent);
                }
            }
            eventBus.publish(errorTask);
            eventBus.publish({ // And publish a final status update
                kind: "status-update",
                taskId: errorTask.id,
                contextId: errorTask.contextId,
                status: errorTask.status,
                final: true,
            } as TaskStatusUpdateEvent);
            eventBus.finished();
        });

        if (isBlocking) {
            // In blocking mode, wait for the full processing to complete.
            await this._processEvents(taskId, resultManager, eventQueue);
            const finalResult = resultManager.getFinalResult();
            if (!finalResult) {
                throw A2AError.internalError('Agent execution finished without a result, and no task context found.');
            }

            return finalResult;
        } else {
            // In non-blocking mode, return a promise that will be settled by fullProcessing.
            return new Promise<Message | Task>((resolve, reject) => {
                this._processEvents(taskId, resultManager, eventQueue, {
                    firstResultResolver: resolve,
                    firstResultRejector: reject,
                });
            });
        }
    }

    async *sendMessageStream(
        params: MessageSendParams
    ): AsyncGenerator<
        | Message
        | Task
        | TaskStatusUpdateEvent
        | TaskArtifactUpdateEvent,
        void,
        undefined
    > {
        const incomingMessage = params.message;
        if (!incomingMessage.messageId) {
            // For streams, messageId might be set by client, or server can generate if not present.
            // Let's assume client provides it or throw for now.
            throw A2AError.invalidParams('message.messageId is required for streaming.');
        }

        const taskId = incomingMessage.taskId || uuidv4();

        // Instantiate ResultManager before creating RequestContext
        const resultManager = new ResultManager(this.taskStore);
        resultManager.setContext(incomingMessage); // Set context for ResultManager

        const requestContext = await this._createRequestContext(incomingMessage, taskId, true);
        const finalMessageForAgent = requestContext.userMessage;

        const eventBus = this.eventBusManager.createOrGetByTaskId(taskId);
        const eventQueue = new ExecutionEventQueue(eventBus);


        // Start agent execution (non-blocking)
        this.agentExecutor.execute(requestContext, eventBus).catch(err => {
            console.error(`Agent execution failed for stream message ${finalMessageForAgent.messageId}:`, err);
            // Publish a synthetic error event if needed
            const errorTaskStatus: TaskStatusUpdateEvent = {
                kind: "status-update",
                taskId: requestContext.task?.id || uuidv4(), // Use existing or a placeholder
                contextId: finalMessageForAgent.contextId!,
                status: {
                    state: "failed",
                    message: {
                        kind: "message",
                        role: "agent",
                        messageId: uuidv4(),
                        parts: [{ kind: "text", text: `Agent execution error: ${err.message}` }],
                        taskId: requestContext.task?.id,
                        contextId: finalMessageForAgent.contextId!,
                    },
                    timestamp: new Date().toISOString(),
                },
                final: true, // This will terminate the stream for the client
            };
            eventBus.publish(errorTaskStatus);
        });

        try {
            for await (const event of eventQueue.events()) {
                await resultManager.processEvent(event); // Update store in background
                yield event; // Stream the event to the client
            }
        } finally {
            // Cleanup when the stream is fully consumed or breaks
            this.eventBusManager.cleanupByTaskId(taskId);
        }
    }

    async getTask(params: TaskQueryParams): Promise<Task> {
        const task = await this.taskStore.load(params.id);
        if (!task) {
            throw A2AError.taskNotFound(params.id);
        }
        if (params.historyLength !== undefined && params.historyLength >= 0) {
            if (task.history) {
                task.history = task.history.slice(-params.historyLength);
            }
        } else {
            // Negative or invalid historyLength means no history
            task.history = [];
        }
        return task;
    }

    async cancelTask(params: TaskIdParams): Promise<Task> {
        const task = await this.taskStore.load(params.id);
        if (!task) {
            throw A2AError.taskNotFound(params.id);
        }

        // Check if task is in a cancelable state
        const nonCancelableStates = ["completed", "failed", "canceled", "rejected"];
        if (nonCancelableStates.includes(task.status.state)) {
            throw A2AError.taskNotCancelable(params.id);
        }

        const eventBus = this.eventBusManager.getByTaskId(params.id);
        
        if(eventBus) {
            await this.agentExecutor.cancelTask(params.id, eventBus);
        }
        else {
            // Here we are marking task as cancelled. We are not waiting for the executor to actually cancel processing.
            task.status = {
                state: "canceled",
                message: { // Optional: Add a system message indicating cancellation
                    kind: "message",
                    role: "agent",
                    messageId: uuidv4(),
                    parts: [{ kind: "text", text: "Task cancellation requested by user." }],
                    taskId: task.id,
                    contextId: task.contextId,
                },
                timestamp: new Date().toISOString(),
            };
            // Add cancellation message to history
            task.history = [...(task.history || []), task.status.message];

            await this.taskStore.save(task);
        }

        const latestTask = await this.taskStore.load(params.id);
        return latestTask;
    }

    async setTaskPushNotificationConfig(
        params: TaskPushNotificationConfig
    ): Promise<TaskPushNotificationConfig> {
        if (!this.agentCard.capabilities.pushNotifications) {
            throw A2AError.pushNotificationNotSupported();
        }
        const taskAndHistory = await this.taskStore.load(params.taskId);
        if (!taskAndHistory) {
            throw A2AError.taskNotFound(params.taskId);
        }
        // Store the config. In a real app, this might be stored in the TaskStore
        // or a dedicated push notification service.
        this.pushNotificationConfigs.set(params.taskId, params.pushNotificationConfig);
        return params;
    }

    async getTaskPushNotificationConfig(
        params: TaskIdParams
    ): Promise<TaskPushNotificationConfig> {
        if (!this.agentCard.capabilities.pushNotifications) {
            throw A2AError.pushNotificationNotSupported();
        }
        const taskAndHistory = await this.taskStore.load(params.id); // Ensure task exists
        if (!taskAndHistory) {
            throw A2AError.taskNotFound(params.id);
        }
        const config = this.pushNotificationConfigs.get(params.id);
        if (!config) {
            throw A2AError.internalError(`Push notification config not found for task ${params.id}.`);
        }
        return { taskId: params.id, pushNotificationConfig: config };
    }

    async *resubscribe(
        params: TaskIdParams
    ): AsyncGenerator<
        | Task // Initial task state
        | TaskStatusUpdateEvent
        | TaskArtifactUpdateEvent,
        void,
        undefined
    > {
        if (!this.agentCard.capabilities.streaming) {
            throw A2AError.unsupportedOperation("Streaming (and thus resubscription) is not supported.");
        }

        const task = await this.taskStore.load(params.id);
        if (!task) {
            throw A2AError.taskNotFound(params.id);
        }

        // Yield the current task state first
        yield task;

        // If task is already in a final state, no more events will come.
        const finalStates = ["completed", "failed", "canceled", "rejected"];
        if (finalStates.includes(task.status.state)) {
            return;
        }

        const eventBus = this.eventBusManager.getByTaskId(params.id);
        if (!eventBus) {
            // No active execution for this task, so no live events.
            console.warn(`Resubscribe: No active event bus for task ${params.id}.`);
            return;
        }

        // Attach a new queue to the existing bus for this resubscription
        const eventQueue = new ExecutionEventQueue(eventBus);
        // Note: The ResultManager part is already handled by the original execution flow.
        // Resubscribe just listens for new events.

        try {
            for await (const event of eventQueue.events()) {
                // We only care about updates related to *this* task.
                // The event bus might be shared if messageId was reused, though
                // ExecutionEventBusManager tries to give one bus per original message.
                if (event.kind === 'status-update' && event.taskId === params.id) {
                    yield event as TaskStatusUpdateEvent;
                } else if (event.kind === 'artifact-update' && event.taskId === params.id) {
                    yield event as TaskArtifactUpdateEvent;
                } else if (event.kind === 'task' && event.id === params.id) {
                    // This implies the task was re-emitted, yield it.
                    yield event as Task;
                }
                // We don't yield 'message' events on resubscribe typically,
                // as those signal the end of an interaction for the *original* request.
                // If a 'message' event for the original request terminates the bus, this loop will also end.
            }
        } finally {
            eventQueue.stop();
        }
    }
}
