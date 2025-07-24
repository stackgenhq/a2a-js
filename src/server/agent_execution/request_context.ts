import {
    Message,
    Task,
} from "../../types.js";

export class RequestContext {
    public readonly userMessage: Message;
    public readonly task?: Task;
    public readonly referenceTasks?: Task[];
    public readonly taskId: string;
    public readonly metadata?: {
        [k: string]: unknown;
    };
    public readonly contextId: string;

    constructor(
        userMessage: Message,
        taskId: string,
        contextId: string,
        task?: Task,
        referenceTasks?: Task[],
        metadata?: {
            [k: string]: unknown;
        }
    ) {
        this.userMessage = userMessage;
        this.taskId = taskId;
        this.contextId = contextId;
        this.task = task;
        this.referenceTasks = referenceTasks;
        this.metadata = metadata;
    }
}
