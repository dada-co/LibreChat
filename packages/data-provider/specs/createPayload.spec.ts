import createPayload from '../src/createPayload';
import { EModelEndpoint } from '../src/schemas';
import type { TSubmission } from '../src/types';

describe('createPayload server URL', () => {
  const base = {
    userMessage: {
      messageId: '1',
      conversationId: 'c1',
      parentMessageId: null,
      text: 'Hello',
      isCreatedByUser: true,
    },
    isTemporary: false,
    messages: [],
    conversation: {
      conversationId: 'c1',
      endpoint: EModelEndpoint.agents,
      title: 'New Chat',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    },
  };

  it('posts agent requests to /api/agents/chat', () => {
    const submission: TSubmission = {
      ...base,
      endpointOption: { endpoint: EModelEndpoint.agents },
    };

    const { server } = createPayload(submission);
    expect(server).toBe('/api/agents/chat');
  });

  it('appends endpoint when not agents', () => {
    const submission: TSubmission = {
      ...base,
      endpointOption: { endpoint: EModelEndpoint.openAI },
    };

    const { server } = createPayload(submission);
    expect(server).toBe(`/api/agents/chat/${EModelEndpoint.openAI}`);
  });
});
