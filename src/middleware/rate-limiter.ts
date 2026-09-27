import rateLimit from 'express-rate-limit';
import { config } from '../config';

export const apiRateLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Rate limit per API Key if available, or by client IP
    const apiKey = (req.headers['key'] as string) || (req.headers['x-api-key'] as string);
    const ip =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() ||
      req.socket.remoteAddress ||
      '127.0.0.1';
    return apiKey ? `key:${apiKey}` : `ip:${ip}`;
  },
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      error: 'Too Many Requests: Rate limit exceeded. Please try again later.',
      retryAfterSeconds: Math.ceil(config.rateLimit.windowMs / 1000),
    });
  },
});
