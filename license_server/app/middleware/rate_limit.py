import redis
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from ..core.config import settings

redis_client = redis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB,
    decode_responses=True
)

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health check
        if request.url.path == "/health":
            return await call_next(request)
        
        client_ip = request.client.host if request.client else "unknown"
        key = f"ratelimit:{client_ip}"
        
        try:
            current = redis_client.get(key)
            
            if current is None:
                redis_client.setex(key, 60, 1)
            else:
                current_count = int(current)
                if current_count >= settings.RATE_LIMIT_PER_MINUTE:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Rate limit exceeded. Please try again later."
                    )
                redis_client.incr(key)
        except redis.RedisError:
            # If Redis is down, allow the request to proceed
            pass
        
        response = await call_next(request)
        return response
