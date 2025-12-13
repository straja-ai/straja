import http from 'k6/http';
import { check } from 'k6';

const BASE_URL = __ENV.STRAJA_BASE_URL || 'http://localhost:8080';
const API_KEY = __ENV.STRAJA_API_KEY || 'local-dev-key-123';
const QPS = Number(__ENV.STRAJA_QPS || 20);
const DURATION = __ENV.STRAJA_DURATION || '60s';
const CONCURRENCY = Number(__ENV.STRAJA_CONCURRENCY || 10);

export const options = {
  scenarios: {
    chat_load: {
      executor: 'constant-arrival-rate',
      rate: QPS,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: CONCURRENCY,
      maxVUs: CONCURRENCY * 2,
    },
  },
};

export default function () {
  const payload = JSON.stringify({
    model: 'gpt-3.5-turbo',
    messages: [
      {
        role: 'user',
        content: 'Hello Straja! This is a quick gateway load test.',
      },
    ],
  });

  const res = http.post(`${BASE_URL}/v1/chat/completions`, payload, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${API_KEY}`,
    },
  });

  check(res, {
    'status is 200/403': (r) => r.status === 200 || r.status === 403,
  });
}
