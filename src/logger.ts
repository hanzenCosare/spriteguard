import pino from 'pino';

export type Logger = pino.Logger;

export function createLogger(level: string): Logger {
  return pino({
    level,
    base: { service: 'spriteguard' },
    redact: {
      paths: ['*.token', '*.apiKey', '*.password', '*.authorization', 'headers.authorization', 'env.*'],
      censor: '[redacted]',
    },
  });
}
