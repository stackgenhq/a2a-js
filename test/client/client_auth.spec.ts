import { describe, it, beforeEach, afterEach } from 'mocha';
import { expect } from 'chai';
import sinon from 'sinon';
import { A2AClient } from '../../src/client/client.js';
import { AuthenticationHandler, HttpHeaders, createAuthenticatingFetchWithRetry } from '../../src/client/auth-handler.js';
import {SendMessageResponse, SendMessageSuccessResponse } from '../../src/types.js';
import { AGENT_CARD_PATH } from '../../src/constants.js';
import { extractRequestId, createResponse, createAgentCardResponse, createMockAgentCard, createMessageParams, createMockMessage } from './util.js';


// Challenge manager class for authentication testing
class ChallengeManager {
  private challengeStore: Set<string> = new Set();

  createChallenge(): string {
    const challenge = Math.random().toString(36).substring(2, 18);  // just a random string
    this.challengeStore.add(challenge);
    return challenge;
  }

  // used by clients to sign challenges
  static signChallenge(challenge: string): string {
    return challenge + '.' + challenge.split('.').reverse().join('');
  }

  // verify the "signature" as simply the reverse of the challenge
  verifyToken(token: string): boolean {
    const [challenge, signature] = token.split('.');
    if (!this.challengeStore.has(challenge))
      return false;

    return signature === challenge.split('.').reverse().join('');
  }

  clearStore(): void {
    this.challengeStore.clear();
  }
}

const challengeManager = new ChallengeManager();

// Factory function to create fresh mock fetch functions
function createMockFetch() {
  return sinon.stub().callsFake(async (url: string, options?: RequestInit) => {
    // Create a fresh mock fetch for each call to avoid Response body reuse issues
    return createFreshMockFetch(url, options);
  });
}

// Helper function to create fresh mock fetch responses
function createFreshMockFetch(url: string, options?: RequestInit) {
  // Simulate agent card fetch
  if (url.includes(AGENT_CARD_PATH)) {
    const mockAgentCard = createMockAgentCard({
      description: 'A test agent for authentication testing'
    });
    
    return createAgentCardResponse(mockAgentCard);
  }
  
  // Simulate RPC endpoint calls
  if (!url.includes('/api'))
    return new Response('Not found', { status: 404 });

  const requestId = extractRequestId(options);
  const authHeader = options?.headers?.['Authorization'] as string;
  
  // If there is no auth header, return a 401 with a challenge that needs to be signed (e.g. using a private key)
  if (!authHeader) {
    const challenge = challengeManager.createChallenge();

    return createResponse(requestId, undefined, {
      code: -32001,
      message: 'Authentication required'
    }, 401, { 'WWW-Authenticate': `Bearer ${challenge}` });
  }

  // All good, return a success response
  const mockMessage = createMockMessage();
  
  return createResponse(requestId, mockMessage);
}

// Mock authentication handler that simulates generating tokens and confirming signatures
class MockAuthHandler implements AuthenticationHandler {
  private authorization: string | null = null;

  async headers(): Promise<HttpHeaders> {
    return this.authorization ? { 'Authorization': this.authorization } : {};
  }

  async shouldRetryWithHeaders(req: RequestInit, res: Response): Promise<HttpHeaders | undefined> {
    // Simulate 401/403 response handling
    if (res.status !== 401 && res.status !== 403)
      return undefined;

    // Parse WWW-Authenticate header to extract the token68/challenge value
    const [scheme, challenge] = res.headers.get('WWW-Authenticate')?.split(/\s+/) || [];
    if (scheme !== 'Bearer')
      return undefined;  // Not the type we expected for this test

    // Use the ChallengeManager to sign the challenge
    const token = ChallengeManager.signChallenge(challenge);
      
    // have the client try the token, BUT don't save it in case the client doesn't accept it
    return { 'Authorization': `Bearer ${token}` };
  }

  async onSuccessfulRetry(headers: HttpHeaders): Promise<void> {
    // Remember successful authorization header
    const auth = headers['Authorization'];
    if (auth)
      this.authorization = auth;
  }
}

// Helper function to check if response is a success response
function isSuccessResponse(response: SendMessageResponse): response is SendMessageSuccessResponse {
  return 'result' in response;
}

describe('A2AClient Authentication Tests', () => {
  let client: A2AClient;
  let authHandler: MockAuthHandler;
  let mockFetch: sinon.SinonStub;
  let originalConsoleError: typeof console.error;

  beforeEach(() => {    
    // Suppress console.error during tests to avoid noise
    originalConsoleError = console.error;
    console.error = () => {};
    
    // Create a fresh mock fetch for each test
    mockFetch = createMockFetch();
    
    authHandler = new MockAuthHandler();
    // Use AuthHandlingFetch to wrap the mock fetch with authentication handling
    const authHandlingFetch = createAuthenticatingFetchWithRetry(mockFetch, authHandler);
    client = new A2AClient('https://test-agent.example.com', {
      fetchImpl: authHandlingFetch
    });
  });

  afterEach(() => {
    // Restore console.error
    console.error = originalConsoleError;
    sinon.restore();
  });

  describe('Authentication Flow', () => {
    it('should handle authentication flow correctly', async () => {
      const messageParams = createMessageParams({
        messageId: 'test-msg-1',
        text: 'Hello, agent!'
      });

      // This should trigger the authentication flow
      const result = await client.sendMessage(messageParams);

      // Verify fetch was called multiple times
      expect(mockFetch.callCount).to.equal(3);
      
      // First call: agent card fetch
      expect(mockFetch.firstCall.args[0]).to.equal(`https://test-agent.example.com/${AGENT_CARD_PATH}`);
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
        method: 'POST'
      });
      // Check headers separately to avoid issues with Authorization header
      expect(mockFetch.thirdCall.args[1].headers).to.have.property('Content-Type', 'application/json');
      expect(mockFetch.thirdCall.args[1].headers).to.have.property('Accept', 'application/json');
      expect(mockFetch.thirdCall.args[1].headers).to.have.property('Authorization');
      
      expect(mockFetch.thirdCall.args[1].headers['Authorization']).to.match(/^Bearer .+$/);
      expect(mockFetch.thirdCall.args[1].body).to.include('"method":"message/send"');

      // Verify the result
      expect(isSuccessResponse(result)).to.be.true;
      if (isSuccessResponse(result)) {
        expect(result.result).to.have.property('kind', 'message');
      }
    });

    it('should reuse authentication token for subsequent requests', async () => {
      const messageParams = createMessageParams({
        messageId: 'test-msg-2',
        text: 'Second message'
      });

      // First request - should trigger auth flow
      const result1 = await client.sendMessage(messageParams);
      
      // Capture the token from the first request
      const firstRequestAuthCall = mockFetch.getCalls().find(call => 
        call.args[0].includes('/api') && 
        call.args[1]?.headers?.['Authorization']
      );
      const firstRequestToken = firstRequestAuthCall?.args[1]?.headers?.['Authorization'];
      
      // Reset calls to clear the first request
      mockFetch.reset();
      
      // Ensure the mock is still properly configured after reset
      mockFetch.callsFake(createFreshMockFetch);
      
      // Second request - should use existing token
      const result2 = await client.sendMessage(messageParams);

      // Should only be called once (no retry needed)
      expect(mockFetch.callCount).to.equal(1);
      
      // Should include auth header immediately from cached token
      expect(mockFetch.firstCall.args[0]).to.equal('https://test-agent.example.com/api');
      expect(mockFetch.firstCall.args[1].headers).to.have.property('Authorization');
      
      // Should use the exact same token from the first request
      expect(mockFetch.firstCall.args[1].headers['Authorization']).to.equal(firstRequestToken);

      expect(isSuccessResponse(result2)).to.be.true;
    });
  });

  describe('Authentication Handler Integration', () => {
    it('should call auth handler methods correctly', async () => {
      const authHandlerSpy = {
        headers: sinon.spy(authHandler, 'headers'),
        shouldRetryWithHeaders: sinon.spy(authHandler, 'shouldRetryWithHeaders'),
        onSuccess: sinon.spy(authHandler, 'onSuccessfulRetry')
      };

      const messageParams = createMessageParams({
        messageId: 'test-msg-4',
        text: 'Test auth handler'
      });

      await client.sendMessage(messageParams);

      // Verify auth handler methods were called
      expect(authHandlerSpy.headers.called).to.be.true;
      expect(authHandlerSpy.shouldRetryWithHeaders.called).to.be.true;
      expect(authHandlerSpy.onSuccess.called).to.be.true;
    });

    it('should handle auth handler returning undefined for retry', async () => {
      // Create a mock that doesn't retry
      const noRetryHandler = new MockAuthHandler();
      const originalShouldRetry = noRetryHandler.shouldRetryWithHeaders.bind(noRetryHandler);
      noRetryHandler.shouldRetryWithHeaders = sinon.stub().resolves(undefined);

      const clientNoRetry = new A2AClient('https://test-agent.example.com', {
        fetchImpl: mockFetch
      });

      const messageParams = createMessageParams({
        messageId: 'test-msg-5',
        text: 'No retry test'
      });

      // This should fail because we're not retrying with auth
      try {
        await clientNoRetry.sendMessage(messageParams);
        expect.fail('Expected error to be thrown');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
      }
    });

    it('should retry with new auth headers', async () => {
      // Create a mock that tracks the Authorization headers sent
      let capturedAuthHeaders: string[] = [];
      const authRetryTestFetch = sinon.stub().callsFake(async (url: string, options?: RequestInit) => {
        if (url.includes(AGENT_CARD_PATH)) {
          const mockAgentCard = createMockAgentCard({
            description: 'A test agent for authentication testing'
          });
          
          return createAgentCardResponse(mockAgentCard);
        }
        
        if (url.includes('/api')) {
          const authHeader = options?.headers?.['Authorization'] as string;
          capturedAuthHeaders.push(authHeader || '');
          
          // First call: no Authorization header, return 401 with WWW-Authenticate header
          if (!authHeader) {
            const requestId = extractRequestId(options);
            return createResponse(requestId, undefined, {
              code: -32001,
              message: 'Authentication required'
            }, 401, { 'WWW-Authenticate': 'Bearer challenge123' });
          }
          
          // Second call: with Authorization header, return success
          const mockMessage = createMockMessage({
            messageId: 'msg-auth-retry',
            text: 'Test auth retry'
          });
          
          const requestId = extractRequestId(options);
          return createResponse(requestId, mockMessage);
        }
        
        return new Response('Not found', { status: 404 });
      });

      const authHandlingFetch = createAuthenticatingFetchWithRetry(authRetryTestFetch, authHandler);
      const clientAuthTest = new A2AClient('https://test-agent.example.com', {
        fetchImpl: authHandlingFetch
      });

      const messageParams = createMessageParams({
        messageId: 'test-msg-auth-retry',
        text: 'Test auth retry'
      });

      // This should trigger the auth flow and succeed
      const result = await clientAuthTest.sendMessage(messageParams);

      // Verify the Authorization headers were sent correctly
      // With AuthHandlingFetch, the auth handler makes the retry internally, so we see both calls
      expect(capturedAuthHeaders).to.have.length(2);
      expect(capturedAuthHeaders[0]).to.equal(''); // First call: no Authorization header
      expect(capturedAuthHeaders[1]).to.be.a('string').and.not.be.empty; // Second call: with Authorization header

      // Verify the result
      expect(isSuccessResponse(result)).to.be.true;
    });

    it('should continue without authentication when server does not return 401', async () => {
      // Create a mock that doesn't require authentication
      let capturedAuthHeaders: string[] = [];
      const noAuthRequiredFetch = sinon.stub().callsFake(async (url: string, options?: RequestInit) => {
        if (url.includes(AGENT_CARD_PATH)) {
          const mockAgentCard = createMockAgentCard({
            description: 'A test agent that does not require authentication'
          });
          
          return createAgentCardResponse(mockAgentCard);
        }
        
        if (url.includes('/api')) {
          const authHeader = options?.headers?.['Authorization'] as string;
          capturedAuthHeaders.push(authHeader || '');
          
          // Always return success without requiring authentication
          const mockMessage = createMockMessage({
            messageId: 'msg-no-auth-required',
            text: 'Test without authentication'
          });
          
          const requestId = extractRequestId(options);
          return createResponse(requestId, mockMessage);
        }
        
        return new Response('Not found', { status: 404 });
      });

      const clientNoAuth = new A2AClient('https://test-agent.example.com', {
        fetchImpl: noAuthRequiredFetch
      });

      const messageParams = createMessageParams({
        messageId: 'test-msg-no-auth',
        text: 'Test without authentication'
      });

      // This should succeed without any authentication flow
      const result = await clientNoAuth.sendMessage(messageParams);

      // Verify that no Authorization headers were sent
      expect(capturedAuthHeaders).to.have.length(1);
      expect(capturedAuthHeaders[0]).to.equal(''); // No auth header sent

      // Verify the result
      expect(isSuccessResponse(result)).to.be.true;
      if (isSuccessResponse(result)) {
        // Check if result is a Message1 (which has messageId) or Task2
        if ('messageId' in result.result) {
          expect(result.result.messageId).to.equal('msg-no-auth-required');
        }
      }
    });

    it('should fail gracefully when no authHandler is provided and server returns 401', async () => {
      // Create a mock that returns 401 without authHandler
      const noAuthHandlerFetch = sinon.stub().callsFake(async (url: string, options?: RequestInit) => {
        if (url.includes(AGENT_CARD_PATH)) {
          const mockAgentCard = createMockAgentCard({
            description: 'A test agent that requires authentication'
          });
          
          return createAgentCardResponse(mockAgentCard);
        }
        
        if (url.includes('/api')) {
          // Always return 401 to simulate authentication required
          // Create a new Response each time to avoid body reuse issues
          const requestId = extractRequestId(options);
          const errorBody = JSON.stringify({
            jsonrpc: '2.0',
            error: {
              code: -32001,
              message: 'Authentication required'
            },
            id: requestId
          });
                    
          return new Response(errorBody, {
            status: 401,
            headers: { 
              'Content-Type': 'application/json',
              'WWW-Authenticate': 'Bearer challenge123'
            }
          });
        }
        
        return new Response('Not found', { status: 404 });
      });

      // Create client WITHOUT authHandler
      const clientNoAuthHandler = new A2AClient('https://test-agent.example.com', {
        fetchImpl: noAuthHandlerFetch
      });

      const messageParams = createMessageParams({
        messageId: 'test-msg-no-auth-handler',
        text: 'Test without auth handler'
      });

      // The client should return a JSON-RPC error response rather than throwing an error
      const result = await clientNoAuthHandler.sendMessage(messageParams);
      
      // Verify that the result is a JSON-RPC error response
      expect(result).to.have.property('jsonrpc', '2.0');
      expect(result).to.have.property('error');
      expect((result as any).error).to.have.property('code', -32001);
      expect((result as any).error).to.have.property('message', 'Authentication required');

      // Verify that fetch was called only once (no retry attempted)
      expect(noAuthHandlerFetch.callCount).to.equal(2); // One for agent card, one for API call
    });
  });
});

describe('AuthHandlingFetch Tests', () => {
  let mockFetch: sinon.SinonStub;
  let authHandler: MockAuthHandler;
  let authHandlingFetch: ReturnType<typeof createAuthenticatingFetchWithRetry>;

  beforeEach(() => {
    mockFetch = createMockFetch();
    authHandler = new MockAuthHandler();
    authHandlingFetch = createAuthenticatingFetchWithRetry(mockFetch, authHandler);
  });

  afterEach(() => {
    sinon.restore();
  });

  describe('Constructor and Function Call', () => {
    it('should create a callable instance', () => {
      expect(typeof authHandlingFetch).to.equal('function');
    });

    it('should support direct function calls', async () => {
      const response = await authHandlingFetch('https://test.example.com/api');
      expect(response).to.be.instanceOf(Response);
    });
  });

  describe('Header Merging', () => {
    it('should merge auth headers with provided headers when auth headers exist', async () => {
      // Create an auth handler that has stored authorization headers
      const authHandlerWithHeaders = new MockAuthHandler();
      
      // Simulate a successful authentication by calling onSuccessfulRetry
      // This will store the Authorization header in the auth handler
      await authHandlerWithHeaders.onSuccessfulRetry({
        'Authorization': 'Bearer test-token-123'
      });
      
      const authHandlingFetchWithHeaders = createAuthenticatingFetchWithRetry(mockFetch, authHandlerWithHeaders);
      
      await authHandlingFetchWithHeaders('https://test.example.com/api', {
        headers: {
          'Content-Type': 'application/json',
          'Custom-Header': 'custom-value'
        }
      });

      // Verify that the fetch was called with merged headers including auth headers
      const fetchCall = mockFetch.getCall(0);
      const headers = fetchCall.args[1]?.headers as Record<string, string>;
      
      // Should include both user headers and auth headers
      expect(headers).to.include({
        'Content-Type': 'application/json',
        'Custom-Header': 'custom-value',
        'Authorization': 'Bearer test-token-123'
      });
      
      // Verify the auth handler's headers method returns the stored authorization
      const storedHeaders = await authHandlerWithHeaders.headers();
      expect(storedHeaders['Authorization']).to.equal('Bearer test-token-123');
    });

    it('should handle empty headers gracefully', async () => {
      const emptyAuthHandler = new MockAuthHandler();
      const emptyAuthFetch = createAuthenticatingFetchWithRetry(mockFetch, emptyAuthHandler);
      
      await emptyAuthFetch('https://test.example.com/api');
      
      const fetchCall = mockFetch.getCall(0);
      expect(fetchCall.args[1]).to.exist;
    });
  });

  describe('Success Callback', () => {
    it('should call onSuccessfulRetry when retry succeeds', async () => {
      const successAuthHandler = new MockAuthHandler();
      const onSuccessSpy = sinon.spy(successAuthHandler, 'onSuccessfulRetry');
      
      // Create a modified version of the existing mockFetch that returns 401 first, then 200
      let callCount = 0;
      const successMockFetch = createMockFetch();
      successMockFetch.callsFake(async (url: string, options?: RequestInit) => {
        callCount++;
        if (callCount === 1) {
          const requestId = extractRequestId(options);
          return createResponse(requestId, undefined, {
            code: -32001,
            message: 'Authentication required'
          }, 401, { 'WWW-Authenticate': 'Bearer challenge123' });
        } else {
          const requestId = extractRequestId(options);
          return createResponse(requestId, { success: true });
        }
      });
      
      const successAuthFetch = createAuthenticatingFetchWithRetry(successMockFetch, successAuthHandler);
      
      await successAuthFetch('https://test.example.com/api');
      
      expect(onSuccessSpy.called).to.be.true;
      expect(onSuccessSpy.firstCall.args[0]).to.deep.include({
        'Authorization': 'Bearer challenge123.challenge123'
      });
    });

    it('should not call onSuccessfulRetry when retry fails', async () => {
      const failAuthHandler = new MockAuthHandler();
      const onSuccessSpy = sinon.spy(failAuthHandler, 'onSuccessfulRetry');
      
      const failFetch = createAuthenticatingFetchWithRetry(mockFetch, failAuthHandler);
      
      // Mock fetch to return 401 first, then 401 again
      let callCount = 0;
      const failMockFetch = createMockFetch();
      failMockFetch.callsFake(async (url: string, options?: RequestInit) => {
        callCount++;
        const requestId = extractRequestId(options);
        return createResponse(requestId, undefined, {
          code: -32001,
          message: 'Authentication required'
        }, 401);
      });
      
      const failAuthFetch = createAuthenticatingFetchWithRetry(failMockFetch, failAuthHandler);
      
      const response = await failAuthFetch('https://test.example.com/api');
      
      expect(onSuccessSpy.called).to.be.false;
      expect(response.status).to.equal(401);
    });
  });

  describe('Error Handling', () => {
    it('should propagate fetch errors', async () => {
      const errorFetch = sinon.stub().rejects(new Error('Network error'));
      const errorAuthFetch = createAuthenticatingFetchWithRetry(errorFetch, authHandler);
      
      try {
        await errorAuthFetch('https://test.example.com/api');
        expect.fail('Expected error to be thrown');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.include('Network error');
      }
    });

    it('should handle auth handler errors gracefully', async () => {
      const errorAuthHandler = new MockAuthHandler();
      const shouldRetrySpy = sinon.stub(errorAuthHandler, 'shouldRetryWithHeaders');
      shouldRetrySpy.rejects(new Error('Auth handler error'));
      
      const errorAuthFetch = createAuthenticatingFetchWithRetry(mockFetch, errorAuthHandler);
      
      try {
        await errorAuthFetch('https://test.example.com/api');
        expect.fail('Expected error to be thrown');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.include('Auth handler error');
      }
    });
  });
});
