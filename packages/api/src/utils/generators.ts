import fetch, { Headers } from 'node-fetch';
import { logger } from '@librechat/data-schemas';
import { GraphEvents, sleep } from '@librechat/agents';
import type { Response as ServerResponse } from 'express';
import type { ServerSentEvent } from '~/types';
import { sendEvent } from './events';

/**
 * Makes a function to make HTTP request and logs the process.
 * @param params
 * @param params.directEndpoint - Whether to use a direct endpoint.
 * @param params.reverseProxyUrl - The reverse proxy URL to use for the request.
 * @returns A promise that resolves to the response of the fetch request.
 */
export function createFetch({
  directEndpoint = false,
  reverseProxyUrl = '',
}: {
  directEndpoint?: boolean;
  reverseProxyUrl?: string;
}) {
  /**
   * Makes an HTTP request and logs the process.
   * @param url - The URL to make the request to. Can be a string or a Request object.
   * @param init - Optional init options for the request.
   * @returns A promise that resolves to the response of the fetch request.
   */
  return async function (
    _url: fetch.RequestInfo,
    init: fetch.RequestInit,
  ): Promise<fetch.Response> {
    let url = _url;
    if (directEndpoint) {
      url = reverseProxyUrl;
    }
    const urlString = typeof url === 'string' ? url : url.toString();

    if (urlString.includes('/responses')) {
      const method = init?.method || 'GET';
      const headers =
        init?.headers instanceof Headers
          ? Object.fromEntries(init.headers.entries())
          : (init?.headers as Record<string, string>) || {};

      if (headers.Authorization) {
        headers.Authorization = '***';
      }

      if (headers['api-key']) {
        headers['api-key'] = '***';
      }

      let body = init?.body as unknown as string | undefined;
      if (body && typeof body !== 'string') {
        try {
          body = JSON.stringify(body);
        } catch {
          body = '[unserializable body]';
        }
      }

      logger.info(`[Responses API] ${method} ${urlString}`);
      logger.debug(`[Responses API Headers] ${JSON.stringify(headers)}`);
      if (body) {
        logger.debug(`[Responses API Body] ${body}`);
        try {
          const parsed = JSON.parse(body);
          if (Array.isArray(parsed?.tools)) {
            for (const tool of parsed.tools) {
              const name =
                tool?.function?.name || tool?.name || tool?.type || 'unknown';
              const params = tool?.function?.parameters ?? tool?.parameters ?? {};
              logger.debug(
                `[Responses API Tool] ${name} ${JSON.stringify(params)}`,
              );
            }
          }
        } catch (err) {
          logger.warn(
            `[Responses API Tool Logging Error] ${(err as Error).message}`,
          );
        }
      }
    }

    logger.debug(`Making request to ${urlString}`);
    if (typeof Bun !== 'undefined') {
      return await fetch(url, init);
    }
    return await fetch(url, init);
  };
}

/**
 * Creates event handlers for stream events that don't capture client references
 * @param res - The response object to send events to
 * @returns Object containing handler functions
 */
export function createStreamEventHandlers(res: ServerResponse) {
  return {
    [GraphEvents.ON_RUN_STEP]: function (event: ServerSentEvent) {
      if (res) {
        sendEvent(res, event);
      }
    },
    [GraphEvents.ON_MESSAGE_DELTA]: function (event: ServerSentEvent) {
      if (res) {
        sendEvent(res, event);
      }
    },
    [GraphEvents.ON_REASONING_DELTA]: function (event: ServerSentEvent) {
      if (res) {
        sendEvent(res, event);
      }
    },
  };
}

export function createHandleLLMNewToken(streamRate: number) {
  return async function () {
    if (streamRate) {
      await sleep(streamRate);
    }
  };
}
