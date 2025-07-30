import 'mocha';
import { assert, expect } from 'chai';
import sinon, { SinonStub, SinonFakeTimers } from 'sinon';

import { AgentExecutor } from '../../src/server/agent_execution/agent_executor.js';
import { describe, beforeEach, afterEach, it } from 'node:test';
import { RequestContext, ExecutionEventBus, TaskStore, InMemoryTaskStore, DefaultRequestHandler, ExecutionEventQueue } from '../../src/server/index.js';
import { AgentCard, Artifact, Message, MessageSendParams, PushNotificationConfig, Task, TaskIdParams, TaskPushNotificationConfig, TaskState, TaskStatusUpdateEvent } from '../../src/index.js';
import { DefaultExecutionEventBusManager, ExecutionEventBusManager } from '../../src/server/events/execution_event_bus_manager.js';
import { A2ARequestHandler } from '../../src/server/request_handler/a2a_request_handler.js';

/**
 * A realistic mock of AgentExecutor for cancellation tests.
 */
class CancellableMockAgentExecutor implements AgentExecutor {
    private cancelledTasks = new Set<string>();
    private clock: SinonFakeTimers;

    constructor(clock: SinonFakeTimers) {
        this.clock = clock;
    }

    public execute = async (
        requestContext: RequestContext,
        eventBus: ExecutionEventBus,
    ): Promise<void> => {
        const taskId = requestContext.taskId;
        const contextId = requestContext.contextId;
        
        eventBus.publish({ id: taskId, contextId, status: { state: "submitted" }, kind: 'task' });
        eventBus.publish({ taskId, contextId, kind: 'status-update', status: { state: "working" }, final: false });
        
        // Simulate a long-running process
        for (let i = 0; i < 5; i++) {
            if (this.cancelledTasks.has(taskId)) {
                eventBus.publish({ taskId, contextId, kind: 'status-update', status: { state: "canceled" }, final: true });
                eventBus.finished();
                return;
            }
            // Use fake timers to simulate work
            await this.clock.tickAsync(100); 
        }

        eventBus.publish({ taskId, contextId, kind: 'status-update', status: { state: "completed" }, final: true });
        eventBus.finished();
    };
    
    public cancelTask = async (
        taskId: string,
        eventBus: ExecutionEventBus,
    ): Promise<void> => {
        this.cancelledTasks.add(taskId);
        // The execute loop is responsible for publishing the final state
    };
    
    // Stub for spying on cancelTask calls
    public cancelTaskSpy = sinon.spy(this, 'cancelTask');
}

describe('DefaultRequestHandler as A2ARequestHandler', () => {
    let handler: A2ARequestHandler;
    let mockTaskStore: TaskStore;
    let mockAgentExecutor: AgentExecutor;
    let executionEventBusManager: ExecutionEventBusManager;
    let clock: SinonFakeTimers;

    const testAgentCard: AgentCard = {
        name: 'Test Agent',
        description: 'An agent for testing purposes',
        url: 'http://localhost:8080',
        version: '1.0.0',
        capabilities: {
            streaming: true,
            pushNotifications: true,
        },
        defaultInputModes: ['text/plain'],
        defaultOutputModes: ['text/plain'],
        skills: [
            {
                id: 'test-skill',
                name: 'Test Skill',
                description: 'A skill for testing',
                tags: ['test'],
            },
        ],
    };

    // Before each test, reset the components to a clean state
    beforeEach(() => {
        mockTaskStore = new InMemoryTaskStore();
        // Default mock for most tests
        mockAgentExecutor = new MockAgentExecutor();
        executionEventBusManager = new DefaultExecutionEventBusManager();
        handler = new DefaultRequestHandler(
            testAgentCard,
            mockTaskStore,
            mockAgentExecutor,
            executionEventBusManager,
        );
    });
    
    // After each test, restore any sinon fakes or stubs
    afterEach(() => {
        sinon.restore();
        if(clock) {
            clock.restore();
        }
    });

    // Helper function to create a basic user message
    const createTestMessage = (id: string, text: string): Message => ({
        messageId: id,
        role: 'user',
        parts: [{ kind: 'text', text }],
        kind: 'message',
    });
    
    /**
     * A mock implementation of AgentExecutor to control agent behavior during tests.
     */
    class MockAgentExecutor implements AgentExecutor {
        // Stubs to control and inspect calls to execute and cancelTask
        public execute: SinonStub<
            [RequestContext, ExecutionEventBus],
            Promise<void>
        > = sinon.stub();
        public cancelTask: SinonStub<[string, ExecutionEventBus], Promise<void>> =
            sinon.stub();
    }

    it('sendMessage: should return a simple message response', async () => {
        const params: MessageSendParams = {
            message: createTestMessage('msg-1', 'Hello'),
        };

        const agentResponse: Message = {
            messageId: 'agent-msg-1',
            role: 'agent',
            parts: [{ kind: 'text', text: 'Hi there!' }],
            kind: 'message',
        };

        (mockAgentExecutor as MockAgentExecutor).execute.callsFake(async (ctx, bus) => {
            bus.publish(agentResponse);
            bus.finished();
        });

        const result = await handler.sendMessage(params);

        assert.deepEqual(result, agentResponse, "The result should be the agent's message");
        assert.isTrue((mockAgentExecutor as MockAgentExecutor).execute.calledOnce, "AgentExecutor.execute should be called once");
    });

    it('sendMessage: (blocking) should return a task in a completed state with an artifact', async () => {
        const params: MessageSendParams = { 
            message: createTestMessage('msg-2', 'Do a task') 
        };

        const taskId = 'task-123';
        const contextId = 'ctx-abc';
        const testArtifact: Artifact = {
            artifactId: 'artifact-1',
            name: 'Test Document',
            description: 'A test artifact.',
            parts: [{ kind: 'text', text: 'This is the content of the artifact.' }]
        };

        (mockAgentExecutor as MockAgentExecutor).execute.callsFake(async (ctx, bus) => {
            bus.publish({
                id: taskId,
                contextId,
                status: { state: "submitted" },
                kind: 'task'
            });
            bus.publish({
                taskId,
                contextId,
                kind: 'status-update',
                status: { state: "working" },
                final: false
            });
            bus.publish({
                taskId,
                contextId,
                kind: 'artifact-update',
                artifact: testArtifact
            });
            bus.publish({
                taskId,
                contextId,
                kind: 'status-update',
                status: { state: "completed", message: { role: 'agent', parts: [{kind: 'text', text: 'Done!'}], messageId: 'agent-msg-2', kind: 'message'} },
                final: true
            });
            bus.finished();
        });

        const result = await handler.sendMessage(params);
        const taskResult = result as Task;

        assert.equal(taskResult.kind, 'task');
        assert.equal(taskResult.id, taskId);
        assert.equal(taskResult.status.state, "completed");
        assert.isDefined(taskResult.artifacts, 'Task result should have artifacts');
        assert.isArray(taskResult.artifacts);
        assert.lengthOf(taskResult.artifacts!, 1);
        assert.deepEqual(taskResult.artifacts![0], testArtifact);
    });

    it('sendMessage: should handle agent execution failure for blocking calls', async () => {
        const errorMessage = 'Agent failed!';
        (mockAgentExecutor as MockAgentExecutor).execute.rejects(new Error(errorMessage));
    
        // Test blocking case
        const blockingParams: MessageSendParams = {
            message: createTestMessage('msg-fail-block', 'Test failure blocking'),
        };
        
        const blockingResult = await handler.sendMessage(blockingParams);
        const blockingTask = blockingResult as Task;
        assert.equal(blockingTask.kind, 'task', 'Result should be a task');
        assert.equal(blockingTask.status.state, 'failed', 'Task status should be failed');
        assert.include((blockingTask.status.message?.parts[0] as any).text, errorMessage, 'Error message should be in the status');
    });

    it('sendMessage: (non-blocking) should return first task event immediately and process full task in background', async () => {
        clock = sinon.useFakeTimers();
        const saveSpy = sinon.spy(mockTaskStore, 'save');

        const params: MessageSendParams = { 
            message: createTestMessage('msg-nonblock', 'Do a long task'),
            configuration: { blocking: false, acceptedOutputModes: [] }
        };

        const taskId = 'task-nonblock-123';
        const contextId = 'ctx-nonblock-abc';

        (mockAgentExecutor as MockAgentExecutor).execute.callsFake(async (ctx, bus) => {
            // First event is the task creation, which should be returned immediately
            bus.publish({
                id: taskId,
                contextId,
                status: { state: "submitted" },
                kind: 'task'
            });

            // Simulate work before publishing more events
            await clock.tickAsync(500);

            bus.publish({
                taskId,
                contextId,
                kind: 'status-update',
                status: { state: "completed" },
                final: true
            });
            bus.finished();
        });

        // This call should return as soon as the first 'task' event is published
        const immediateResult = await handler.sendMessage(params);
        
        // Assert that we got the initial task object back right away
        const taskResult = immediateResult as Task;
        assert.equal(taskResult.kind, 'task');
        assert.equal(taskResult.id, taskId);
        assert.equal(taskResult.status.state, 'submitted', "Should return immediately with 'submitted' state");

        // The background processing should not have completed yet
        assert.isTrue(saveSpy.calledOnce, "Save should be called for the initial task creation");
        assert.equal(saveSpy.firstCall.args[0].status.state, 'submitted');

        // Allow the background processing to complete
        await clock.runAllAsync();
        
        // Now, check the final state in the store to ensure background processing finished
        const finalTask = await mockTaskStore.load(taskId);
        assert.isDefined(finalTask);
        assert.equal(finalTask!.status.state, 'completed', "Task should be 'completed' in the store after background processing");
        assert.isTrue(saveSpy.calledTwice, "Save should be called twice (submitted and completed)");
        assert.equal(saveSpy.secondCall.args[0].status.state, 'completed');
    });

    it('sendMessage: should handle agent execution failure for non-blocking calls', async () => {
        const errorMessage = 'Agent failed!';
        (mockAgentExecutor as MockAgentExecutor).execute.rejects(new Error(errorMessage));
    
        // Test non-blocking case
        const nonBlockingParams: MessageSendParams = {
            message: createTestMessage('msg-fail-nonblock', 'Test failure non-blocking'),
            configuration: { blocking: false, acceptedOutputModes: [] },
        };

        const nonBlockingResult = await handler.sendMessage(nonBlockingParams);
        const nonBlockingTask = nonBlockingResult as Task;
        assert.equal(nonBlockingTask.kind, 'task', 'Result should be a task');
        assert.equal(nonBlockingTask.status.state, 'failed', 'Task status should be failed');
        assert.include((nonBlockingTask.status.message?.parts[0] as any).text, errorMessage, 'Error message should be in the status');
    });

    it('sendMessageStream: should stream submitted, working, and completed events', async () => {
        const params: MessageSendParams = { 
            message: createTestMessage('msg-3', 'Stream a task') 
        };
        const taskId = 'task-stream-1';
        const contextId = 'ctx-stream-1';

        (mockAgentExecutor as MockAgentExecutor).execute.callsFake(async (ctx, bus) => {
            bus.publish({ id: taskId, contextId, status: { state: "submitted" }, kind: 'task' });
            await new Promise(res => setTimeout(res, 10));
            bus.publish({ taskId, contextId, kind: 'status-update', status: { state: "working" }, final: false });
            await new Promise(res => setTimeout(res, 10));
            bus.publish({ taskId, contextId, kind: 'status-update', status: { state: "completed" }, final: true });
            bus.finished();
        });
        
        const eventGenerator = handler.sendMessageStream(params);
        const events = [];
        for await (const event of eventGenerator) {
            events.push(event);
        }

        assert.lengthOf(events, 3, "Stream should yield 3 events");
        assert.equal((events[0] as Task).status.state, "submitted");
        assert.equal((events[1] as TaskStatusUpdateEvent).status.state, "working");
        assert.equal((events[2] as TaskStatusUpdateEvent).status.state, "completed");
        assert.isTrue((events[2] as TaskStatusUpdateEvent).final);
    });

    it('sendMessage: should reject if task is in a terminal state', async () => {
        const taskId = 'task-terminal-1';
        const terminalStates: TaskState[] = ['completed', 'failed', 'canceled', 'rejected'];

        for (const state of terminalStates) {
            const fakeTask: Task = {
                id: taskId,
                contextId: 'ctx-terminal',
                status: { state: state as TaskState },
                kind: 'task'
            };
            await mockTaskStore.save(fakeTask);

            const params: MessageSendParams = {
                message: { ...createTestMessage('msg-1', 'test'), taskId: taskId }
            };

            try {
                await handler.sendMessage(params);
                assert.fail(`Should have thrown for state: ${state}`);
            } catch (error: any) {
                expect(error.code).to.equal(-32600); // Invalid Request
                expect(error.message).to.contain(`Task ${taskId} is in a terminal state (${state}) and cannot be modified.`);
            }
        }
    });

    it('sendMessageStream: should reject if task is in a terminal state', async () => {
        const taskId = 'task-terminal-2';
        const fakeTask: Task = {
            id: taskId,
            contextId: 'ctx-terminal-stream',
            status: { state: 'completed' },
            kind: 'task'
        };
        await mockTaskStore.save(fakeTask);

        const params: MessageSendParams = {
            message: { ...createTestMessage('msg-1', 'test'), taskId: taskId }
        };

        const generator = handler.sendMessageStream(params);

        try {
            await generator.next();
            assert.fail('sendMessageStream should have thrown an error');
        } catch(error: any) {
            expect(error.code).to.equal(-32600);
            expect(error.message).to.contain(`Task ${taskId} is in a terminal state (completed) and cannot be modified.`);
        }
    });

    it('sendMessageStream: should stop at input-required state', async () => {
        const params: MessageSendParams = {
            message: createTestMessage('msg-4', 'I need input')
        };
        const taskId = 'task-input';
        const contextId = 'ctx-input';

        (mockAgentExecutor as MockAgentExecutor).execute.callsFake(async (ctx, bus) => {
            bus.publish({ id: taskId, contextId, status: { state: "submitted" }, kind: 'task' });
            bus.publish({ taskId, contextId, kind: 'status-update', status: { state: "input-required" }, final: true });
            bus.finished();
        });
        
        const eventGenerator = handler.sendMessageStream(params);
        const events = [];
        for await (const event of eventGenerator) {
            events.push(event);
        }

        assert.lengthOf(events, 2);
        const lastEvent = events[1] as TaskStatusUpdateEvent;
        assert.equal(lastEvent.status.state, "input-required");
        assert.isTrue(lastEvent.final);
    });

    it('resubscribe: should allow multiple clients to receive events for the same task', async () => {
        const saveSpy = sinon.spy(mockTaskStore, 'save');
        clock = sinon.useFakeTimers();
        const params: MessageSendParams = {
            message: createTestMessage('msg-5', 'Long running task')
        };

        let taskId;
        let contextId;
    
        (mockAgentExecutor as MockAgentExecutor).execute.callsFake(async (ctx, bus) => {
            taskId = ctx.taskId;
            contextId = ctx.contextId;

            bus.publish({ id: taskId, contextId, status: { state: "submitted" }, kind: 'task' });
            bus.publish({ taskId, contextId, kind: 'status-update', status: { state: "working" }, final: false });
            await clock.tickAsync(100);
            bus.publish({ taskId, contextId, kind: 'status-update', status: { state: "completed" }, final: true });
            bus.finished();
        });
    
        const stream1_generator = handler.sendMessageStream(params);
        const stream1_iterator = stream1_generator[Symbol.asyncIterator]();
    
        const firstEventResult = await stream1_iterator.next();
        const firstEvent = firstEventResult.value as Task;
        assert.equal(firstEvent.id, taskId, 'Should get task event first');

        const secondEventResult = await stream1_iterator.next();
        const secondEvent = secondEventResult.value as TaskStatusUpdateEvent;
        assert.equal(secondEvent.taskId, taskId, 'Should get the task status update event second');
    
        const stream2_generator = handler.resubscribe({ id: taskId });
    
        const results1: any[] = [firstEvent, secondEvent];
        const results2: any[] = [];
    
        const collect = async (iterator: AsyncGenerator<any>, results: any[]) => {
            for await (const res of iterator) {
                results.push(res);
            }
        };
    
        const p1 = collect(stream1_iterator, results1);
        const p2 = collect(stream2_generator, results2);
    
        await clock.runAllAsync();
        await Promise.all([p1, p2]);

        assert.equal((results1[0] as TaskStatusUpdateEvent).status.state, "submitted");
        assert.equal((results1[1] as TaskStatusUpdateEvent).status.state, "working");
        assert.equal((results1[2] as TaskStatusUpdateEvent).status.state, "completed");

        // First event of resubscribe is always a task.
        assert.equal((results2[0] as Task).status.state, "working");
        assert.equal((results2[1] as TaskStatusUpdateEvent).status.state, "completed");
        
        assert.isTrue(saveSpy.calledThrice, 'TaskStore.save should be called 3 times');
        const lastSaveCall = saveSpy.lastCall.args[0];
        assert.equal(lastSaveCall.id, taskId);
        assert.equal(lastSaveCall.status.state, "completed");
    });
    
    it('getTask: should return an existing task from the store', async () => {
        const fakeTask: Task = {
            id: 'task-exist',
            contextId: 'ctx-exist',
            status: { state: "working" },
            kind: 'task',
            history: []
        };
        await mockTaskStore.save(fakeTask);

        const result = await handler.getTask({ id: 'task-exist' });
        assert.deepEqual(result, fakeTask);
    });

    it('set/getTaskPushNotificationConfig: should save and retrieve config', async () => {
        const taskId = 'task-push-config';
        const fakeTask: Task = { id: taskId, contextId: 'ctx-push', status: { state: "working" }, kind: 'task' };
        await mockTaskStore.save(fakeTask);
    
        const pushConfig: PushNotificationConfig = {
            url: 'https://example.com/notify',
            token: 'secret-token'
        };
    
        const setParams: TaskPushNotificationConfig = { taskId, pushNotificationConfig: pushConfig };
        const setResponse = await handler.setTaskPushNotificationConfig(setParams);
        assert.deepEqual(setResponse.pushNotificationConfig, pushConfig, "Set response should return the config");
    
        const getParams: TaskIdParams = { id: taskId };
        const getResponse = await handler.getTaskPushNotificationConfig(getParams);
        assert.deepEqual(getResponse.pushNotificationConfig, pushConfig, "Get response should return the saved config");
    });
    
    it('cancelTask: should cancel a running task and notify listeners', async () => {
        clock = sinon.useFakeTimers();
        // Use the more advanced mock for this specific test
        const cancellableExecutor = new CancellableMockAgentExecutor(clock);
        handler = new DefaultRequestHandler(
            testAgentCard,
            mockTaskStore,
            cancellableExecutor,
            executionEventBusManager,
        );

        const streamParams: MessageSendParams = { message: createTestMessage('msg-9', 'Start and cancel') };
        const streamGenerator = handler.sendMessageStream(streamParams);
        
        const streamEvents: any[] = [];
        const streamingPromise = (async () => {
            for await (const event of streamGenerator) {
                streamEvents.push(event);
            }
        })();

        // Allow the task to be created and enter the 'working' state
        await clock.tickAsync(150); 
        
        const createdTask = streamEvents.find(e => e.kind === 'task') as Task;
        assert.isDefined(createdTask, 'Task creation event should have been received');
        const taskId = createdTask.id;

        // Now, issue the cancel request
        const cancelResponse = await handler.cancelTask({ id: taskId });

        // Let the executor's loop run to completion to detect the cancellation
        await clock.runAllAsync();
        await streamingPromise;

        assert.isTrue(cancellableExecutor.cancelTaskSpy.calledOnceWith(taskId, sinon.match.any));
        
        const lastEvent = streamEvents[streamEvents.length - 1] as TaskStatusUpdateEvent;
        assert.equal(lastEvent.status.state, "canceled");
        
        const finalTask = await handler.getTask({ id: taskId });
        assert.equal(finalTask.status.state, "canceled");

        // Canceled API issues cancel request to executor and returns latest task state.
        // In this scenario, executor is waiting on clock to detect that task has been cancelled.
        // While the cancel API has returned with latest task state => Working.
        assert.equal(cancelResponse.status.state, "working");
    });

    it('cancelTask: should fail for tasks in a terminal state', async () => {
        const taskId = 'task-terminal';
        const fakeTask: Task = { id: taskId, contextId: 'ctx-terminal', status: { state: "completed" }, kind: 'task' };
        await mockTaskStore.save(fakeTask);

        try {
            await handler.cancelTask({ id: taskId });
            assert.fail('Should have thrown a TaskNotCancelableError');
        } catch (error: any) {
            assert.equal(error.code, -32002);
            expect(error.message).to.contain('Task not cancelable');
        }
        assert.isFalse((mockAgentExecutor as MockAgentExecutor).cancelTask.called);
    });

    it('should use contextId from incomingMessage if present (contextId assignment logic)', async () => {
        const params: MessageSendParams = {
            message: {
                messageId: 'msg-ctx',
                role: 'user',
                parts: [{ kind: 'text', text: 'Hello' }],
                kind: 'message',
                contextId: 'incoming-ctx-id',
            },
        };
        let capturedContextId: string | undefined;
        (mockAgentExecutor.execute as SinonStub).callsFake(async (ctx, bus) => {
            capturedContextId = ctx.contextId;
            bus.publish({
                id: ctx.taskId,
                contextId: ctx.contextId,
                status: { state: "submitted" },
                kind: 'task'
            });
            bus && bus.finished && bus.finished();
        });
        await handler.sendMessage(params);
        expect(capturedContextId).to.equal('incoming-ctx-id');
    });

    it('should use contextId from task if not present in incomingMessage (contextId assignment logic)', async () => {
        const taskId = 'task-ctx-id';
        const taskContextId = 'task-context-id';
        await mockTaskStore.save({
            id: taskId,
            contextId: taskContextId,
            status: { state: 'working' },
            kind: 'task',
        });
        const params: MessageSendParams = {
            message: {
                messageId: 'msg-ctx2',
                role: 'user',
                parts: [{ kind: 'text', text: 'Hi' }],
                kind: 'message',
                taskId,
            },
        };
        let capturedContextId: string | undefined;
        (mockAgentExecutor.execute as SinonStub).callsFake(async (ctx, bus) => {
            capturedContextId = ctx.contextId;
            bus.publish({
                id: ctx.taskId,
                contextId: ctx.contextId,
                status: { state: "submitted" },
                kind: 'task'
            });
            bus && bus.finished && bus.finished();
        });
        await handler.sendMessage(params);
        expect(capturedContextId).to.equal(taskContextId);
    });

    it('should generate a new contextId if not present in message or task (contextId assignment logic)', async () => {
        const params: MessageSendParams = {
            message: {
                messageId: 'msg-ctx3',
                role: 'user',
                parts: [{ kind: 'text', text: 'Hey' }],
                kind: 'message',
            },
        };
        let capturedContextId: string | undefined;
        (mockAgentExecutor.execute as SinonStub).callsFake(async (ctx, bus) => {
            capturedContextId = ctx.contextId;
            bus.publish({
                id: ctx.taskId,
                contextId: ctx.contextId,
                status: { state: "submitted" },
                kind: 'task'
            });
            bus && bus.finished && bus.finished();
        });
        await handler.sendMessage(params);
        expect(capturedContextId).to.be.a('string').and.not.empty;
    });
      
    it('ExecutionEventQueue should be instantiable and return an object', () => {
        const fakeBus = {
            on: () => {},
            off: () => {}
        } as any;
        const queue = new ExecutionEventQueue(fakeBus);
        expect(queue).to.be.instanceOf(ExecutionEventQueue);
    });
});
