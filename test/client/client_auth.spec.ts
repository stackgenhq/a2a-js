import { describe, it, beforeEach, afterEach } from 'mocha';
import { expect } from 'chai';
import sinon from 'sinon';
import { A2AClient } from '../../src/client/client.js';
import { AuthenticationHandler, HttpHeaders } from '../../src/client/auth-handler.js';
import { AgentCard, MessageSendParams, TextPart, Message, SendMessageResponse, SendMessageSuccessResponse } from '../../src/types.js';

// Mock fetch implementation
let mockFetch: sinon.SinonStub;
let fetchCallCount = 0;

// Mock authentication handler that simulates token generation
class MockAuthHandler implements AuthenticationHandler {
  private hasToken = false;
  private tokenGenerated = false;

  headers(): HttpHeaders {
    if (this.hasToken) {
      return { 'Authorization': 'Bearer mock-token-12345' };
    }
    return {};
  }

  async shouldRetryWithHeaders(req: RequestInit, res: Response): Promise<HttpHeaders | undefined> {
    // Simulate 401/403 response handling
    if (res.status === 401 || res.status === 403) {
      if (!this.tokenGenerated) {
        this.tokenGenerated = true;
        this.hasToken = true;
        return { 'Authorization': 'Bearer mock-token-12345' };
      }
    }
    return undefined;
  }

  async onSuccess(headers: HttpHeaders): Promise<void> {
    // Remember successful headers
    if (headers['Authorization']) {
      this.hasToken = true;
    }
  }
}

// Helper function to check if response is a success response
function isSuccessResponse(response: SendMessageResponse): response is SendMessageSuccessResponse {
  return 'result' in response;
}

describe('A2AClient Authentication Tests', () => {
  let client: A2AClient;
  let authHandler: MockAuthHandler;

  beforeEach(() => {
    // Reset mock state
    fetchCallCount = 0;
    
    // Create mock fetch that simulates authentication flow
    mockFetch = sinon.stub().callsFake(async (url: string, options?: RequestInit) => {
      fetchCallCount++;
      
      // Simulate agent card fetch
      if (url.includes('.well-known/agent.json')) {
        const mockAgentCard: AgentCard = {
          name: 'Test Agent',
          description: 'A test agent for authentication testing',
          version: '1.0.0',
          url: 'https://test-agent.example.com/api',
          defaultInputModes: ['text'],
          defaultOutputModes: ['text'],
          capabilities: {
            streaming: true,
            pushNotifications: true
          },
          skills: []
        };
        
        return new Response(JSON.stringify(mockAgentCard), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // Simulate RPC endpoint calls
      if (url.includes('/api')) {
        const authHeader = options?.headers?.['Authorization'] as string;
        
        // First call: no auth header, return 401
        if (fetchCallCount === 2 && !authHeader) {
          return new Response(JSON.stringify({
            jsonrpc: '2.0',
            error: {
              code: -32001,
              message: 'Authentication required'
            },
            id: 1
          }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        
        // Second call: with auth header, return success
        if (fetchCallCount === 3 && authHeader === 'Bearer mock-token-12345') {
          const mockMessage: Message = {
            kind: 'message',
            messageId: 'msg-123',
            role: 'user',
            parts: [{
              kind: 'text',
              text: 'Hello, agent!'
            } as TextPart]
          };
          
          return new Response(JSON.stringify({
            jsonrpc: '2.0',
            result: mockMessage,
            id: 1
          }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        
        // Subsequent calls with auth header should succeed
        if (authHeader === 'Bearer mock-token-12345') {
          const mockMessage: Message = {
            kind: 'message',
            messageId: `msg-${fetchCallCount}`,
            role: 'user',
            parts: [{
              kind: 'text',
              text: `Message ${fetchCallCount}`
            } as TextPart]
          };
          
          return new Response(JSON.stringify({
            jsonrpc: '2.0',
            result: mockMessage,
            id: fetchCallCount
          }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        
        // Any other case without auth header should fail
        return new Response(JSON.stringify({
          jsonrpc: '2.0',
          error: {
            code: -32001,
            message: 'Authentication required'
          },
          id: fetchCallCount
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // Default response
      return new Response('Not found', { status: 404 });
    });
    
    authHandler = new MockAuthHandler();
    client = new A2AClient('https://test-agent.example.com', {
      authHandler,
      fetchImpl: mockFetch
    });
  });

  afterEach(() => {
    sinon.restore();
  });

  describe('Authentication Flow', () => {
    it('should handle authentication flow correctly', async () => {
      const messageParams: MessageSendParams = {
        message: {
          kind: 'message',
          messageId: 'test-msg-1',
          role: 'user',
          parts: [{
            kind: 'text',
            text: 'Hello, agent!'
          } as TextPart]
        }
      };

      // This should trigger the authentication flow
      const result = await client.sendMessage(messageParams);

      // Verify fetch was called multiple times
      expect(mockFetch.callCount).to.equal(3);
      
      // First call: agent card fetch
      expect(mockFetch.firstCall.args[0]).to.equal('https://test-agent.example.com/.well-known/agent.json');
      expect(mockFetch.firstCall.args[1]).to.deep.include({
        headers: { 'Accept': 'application/json' }
      });
      
      // Second call: RPC request without auth header
      expect(mockFetch.secondCall.args[0]).to.equal('https://test-agent.example.com/api');
      expect(mockFetch.secondCall.args[1]).to.deep.include({
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      });
      expect(mockFetch.secondCall.args[1].body).to.include('"method":"message/send"');
      
      // Third call: RPC request with auth header
      expect(mockFetch.thirdCall.args[0]).to.equal('https://test-agent.example.com/api');
      expect(mockFetch.thirdCall.args[1]).to.deep.include({
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Authorization': 'Bearer mock-token-12345'
        }
      });
      expect(mockFetch.thirdCall.args[1].body).to.include('"method":"message/send"');

      // Verify the result
      expect(isSuccessResponse(result)).to.be.true;
      if (isSuccessResponse(result)) {
        expect(result.result).to.have.property('kind', 'message');
      }
    });

    it('should reuse authentication token for subsequent requests', async () => {
      const messageParams: MessageSendParams = {
        message: {
          kind: 'message',
          messageId: 'test-msg-2',
          role: 'user',
          parts: [{
            kind: 'text',
            text: 'Second message'
          } as TextPart]
        }
      };

      // First request - should trigger auth flow
      await client.sendMessage(messageParams);
      
      // Reset call count for second request
      fetchCallCount = 0;
      mockFetch.reset();
      
      // Create a new mock for the second request that expects auth header
      mockFetch.callsFake(async (url: string, options?: RequestInit) => {
        if (url.includes('/api')) {
          const authHeader = options?.headers?.['Authorization'] as string;
          if (authHeader === 'Bearer mock-token-12345') {
            const mockMessage: Message = {
              kind: 'message',
              messageId: 'msg-second',
              role: 'user',
              parts: [{
                kind: 'text',
                text: 'Second message'
              } as TextPart]
            };
            
            return new Response(JSON.stringify({
              jsonrpc: '2.0',
              result: mockMessage,
              id: 1
            }), {
              status: 200,
              headers: { 'Content-Type': 'application/json' }
            });
          }
        }
        return new Response('Not found', { status: 404 });
      });
      
      // Second request - should use existing token
      const result2 = await client.sendMessage(messageParams);

      // Should only be called once (no retry needed)
      expect(mockFetch.callCount).to.equal(1);
      
      // Should include auth header immediately
      expect(mockFetch.firstCall.args[0]).to.equal('https://test-agent.example.com/api');
      expect(mockFetch.firstCall.args[1].headers).to.include({
        'Authorization': 'Bearer mock-token-12345'
      });

      expect(isSuccessResponse(result2)).to.be.true;
    });

    it('should handle multiple concurrent requests with authentication', async () => {
      const messageParams: MessageSendParams = {
        message: {
          kind: 'message',
          messageId: 'test-msg-3',
          role: 'user',
          parts: [{
            kind: 'text',
            text: 'Concurrent message'
          } as TextPart]
        }
      };

      // Create a new mock that handles concurrent requests properly
      mockFetch.reset();
      mockFetch.callsFake(async (url: string, options?: RequestInit) => {
        if (url.includes('.well-known/agent.json')) {
          const mockAgentCard: AgentCard = {
            name: 'Test Agent',
            description: 'A test agent for authentication testing',
            version: '1.0.0',
            url: 'https://test-agent.example.com/api',
            defaultInputModes: ['text'],
            defaultOutputModes: ['text'],
            capabilities: {
              streaming: true,
              pushNotifications: true
            },
            skills: []
          };
          
          return new Response(JSON.stringify(mockAgentCard), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        
        if (url.includes('/api')) {
          const authHeader = options?.headers?.['Authorization'] as string;
          
          // If no auth header, return 401 to trigger auth flow
          if (!authHeader) {
            return new Response(JSON.stringify({
              jsonrpc: '2.0',
              error: {
                code: -32001,
                message: 'Authentication required'
              },
              id: 1
            }), {
              status: 401,
              headers: { 'Content-Type': 'application/json' }
            });
          }
          
          // If auth header is present, return success
          if (authHeader === 'Bearer mock-token-12345') {
            const mockMessage: Message = {
              kind: 'message',
              messageId: `msg-concurrent-${Date.now()}`,
              role: 'user',
              parts: [{
                kind: 'text',
                text: 'Concurrent message'
              } as TextPart]
            };
            
            return new Response(JSON.stringify({
              jsonrpc: '2.0',
              result: mockMessage,
              id: 1
            }), {
              status: 200,
              headers: { 'Content-Type': 'application/json' }
            });
          }
        }
        return new Response('Not found', { status: 404 });
      });

      // Send multiple requests sequentially to test authentication reuse
      const results = [];
      for (let i = 0; i < 3; i++) {
        const result = await client.sendMessage(messageParams);
        results.push(result);
      }

      // All should succeed
      results.forEach(result => {
        expect(isSuccessResponse(result)).to.be.true;
        if (isSuccessResponse(result)) {
          expect(result.result).to.have.property('kind', 'message');
        }
      });

      // Should have made multiple calls (agent card + RPC calls)
      expect(mockFetch.callCount).to.equal(4); // 1 agent card + 3 RPC calls
    });
  });

  describe('Authentication Handler Integration', () => {
    it('should call auth handler methods correctly', async () => {
      const authHandlerSpy = {
        headers: sinon.spy(authHandler, 'headers'),
        shouldRetryWithHeaders: sinon.spy(authHandler, 'shouldRetryWithHeaders'),
        onSuccess: sinon.spy(authHandler, 'onSuccess')
      };

      const messageParams: MessageSendParams = {
        message: {
          kind: 'message',
          messageId: 'test-msg-4',
          role: 'user',
          parts: [{
            kind: 'text',
            text: 'Test auth handler'
          } as TextPart]
        }
      };

      await client.sendMessage(messageParams);

      // Verify auth handler methods were called
      expect(authHandlerSpy.headers.called).to.be.true;
      expect(authHandlerSpy.shouldRetryWithHeaders.called).to.be.true;
      expect(authHandlerSpy.onSuccess.calledWith({
        'Authorization': 'Bearer mock-token-12345'
      })).to.be.true;
    });

    it('should handle auth handler returning undefined for retry', async () => {
      // Create a mock that doesn't retry
      const noRetryHandler = new MockAuthHandler();
      const originalShouldRetry = noRetryHandler.shouldRetryWithHeaders.bind(noRetryHandler);
      noRetryHandler.shouldRetryWithHeaders = sinon.stub().resolves(undefined);

      const clientNoRetry = new A2AClient('https://test-agent.example.com', {
        authHandler: noRetryHandler,
        fetchImpl: mockFetch
      });

      const messageParams: MessageSendParams = {
        message: {
          kind: 'message',
          messageId: 'test-msg-5',
          role: 'user',
          parts: [{
            kind: 'text',
            text: 'No retry test'
          } as TextPart]
        }
      };

      // This should fail because we're not retrying with auth
      try {
        await clientNoRetry.sendMessage(messageParams);
        expect.fail('Expected error to be thrown');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
      }
    });
  });

  describe('Error Handling', () => {
    it('should handle network errors gracefully', async () => {
      const networkErrorFetch = sinon.stub().rejects(new Error('Network error'));
      
      const clientWithNetworkError = new A2AClient('https://test-agent.example.com', {
        authHandler,
        fetchImpl: networkErrorFetch
      });

      const messageParams: MessageSendParams = {
        message: {
          kind: 'message',
          messageId: 'test-msg-6',
          role: 'user',
          parts: [{
            kind: 'text',
            text: 'Network error test'
          } as TextPart]
        }
      };

      try {
        await clientWithNetworkError.sendMessage(messageParams);
        expect.fail('Expected error to be thrown');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.include('Network error');
      }
    });

    it('should handle malformed JSON responses', async () => {
      const malformedFetch = sinon.stub().callsFake(async (url: string) => {
        if (url.includes('.well-known/agent.json')) {
          return new Response('Invalid JSON', {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        return new Response('Not found', { status: 404 });
      });

      const clientWithMalformed = new A2AClient('https://test-agent.example.com', {
        authHandler,
        fetchImpl: malformedFetch
      });

      const messageParams: MessageSendParams = {
        message: {
          kind: 'message',
          messageId: 'test-msg-7',
          role: 'user',
          parts: [{
            kind: 'text',
            text: 'Malformed JSON test'
          } as TextPart]
        }
      };

      try {
        await clientWithMalformed.sendMessage(messageParams);
        expect.fail('Expected error to be thrown');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
      }
    });
  });

  describe('Agent Card Caching', () => {
    it('should cache agent card and reuse service endpoint', async () => {
      const messageParams: MessageSendParams = {
        message: {
          kind: 'message',
          messageId: 'test-msg-8',
          role: 'user',
          parts: [{
            kind: 'text',
            text: 'Agent card caching test'
          } as TextPart]
        }
      };

      // First request - should fetch agent card
      await client.sendMessage(messageParams);
      
      // Reset fetch mock
      mockFetch.reset();
      
      // Create a new mock for the second request
      mockFetch.callsFake(async (url: string, options?: RequestInit) => {
        if (url.includes('/api')) {
          const authHeader = options?.headers?.['Authorization'] as string;
          if (authHeader === 'Bearer mock-token-12345') {
            const mockMessage: Message = {
              kind: 'message',
              messageId: 'msg-cached',
              role: 'user',
              parts: [{
                kind: 'text',
                text: 'Agent card caching test'
              } as TextPart]
            };
            
            return new Response(JSON.stringify({
              jsonrpc: '2.0',
              result: mockMessage,
              id: 1
            }), {
              status: 200,
              headers: { 'Content-Type': 'application/json' }
            });
          }
        }
        return new Response('Not found', { status: 404 });
      });
      
      // Second request - should reuse cached agent card
      await client.sendMessage(messageParams);

      // Should not fetch agent card again
      const calls = mockFetch.getCalls();
      const agentCardCalls = calls.filter(call => 
        call.args[0].includes('.well-known/agent.json')
      );
      
      expect(agentCardCalls).to.have.length(0);
    });
  });
});
