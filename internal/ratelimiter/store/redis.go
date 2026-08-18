package store

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// incrScript atomically increments a counter and applies a TTL only the
// first time the key is created, matching Store.Increment's contract
// that the ttl is fixed at creation and not refreshed by later calls.
const incrScript = `
local current = redis.call("INCR", KEYS[1])
if current == 1 then
	redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return current
`

// casScript implements compare-and-swap on an arbitrary string value.
// ARGV[1] is "1" if the caller expects the key to currently exist with
// value ARGV[2] ("0" means the caller expects the key to be absent).
// ARGV[3] is the new value, ARGV[4] the TTL in milliseconds (0 = none).
const casScript = `
local exists = redis.call("EXISTS", KEYS[1])
if ARGV[1] == "1" then
	if exists == 0 then
		return 0
	end
	if redis.call("GET", KEYS[1]) ~= ARGV[2] then
		return 0
	end
else
	if exists == 1 then
		return 0
	end
end
redis.call("SET", KEYS[1], ARGV[3])
local ttl = tonumber(ARGV[4])
if ttl > 0 then
	redis.call("PEXPIRE", KEYS[1], ttl)
end
return 1
`

// RedisStore is a Store backed by Redis, for coordinating rate limits
// across multiple Gatekeeper instances. Increment and CompareAndSwap are
// each one Lua script rather than a sequence of separate Redis calls,
// because the read-modify-write they do needs to be atomic — and Lua
// scripts are how you get that from Redis. MemoryStore gets the same
// guarantee for free from its mutex; RedisStore has to earn it.
type RedisStore struct {
	client *redis.Client
}

// NewRedisStore creates a RedisStore. It doesn't check connectivity on its
// own — call Ping for that (cmd/gatekeeper's fallback logic does exactly
// this) before deciding whether Redis is actually usable.
func NewRedisStore(addr, password string, db int, dialTimeout time.Duration) *RedisStore {
	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		Password:    password,
		DB:          db,
		DialTimeout: dialTimeout,
	})
	return &RedisStore{client: client}
}

// Increment implements Store.
func (s *RedisStore) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	res, err := s.client.Eval(ctx, incrScript, []string{key}, ttl.Milliseconds()).Result()
	if err != nil {
		return 0, err
	}
	return toInt64(res)
}

// Load implements Store.
func (s *RedisStore) Load(ctx context.Context, key string) ([]byte, error) {
	val, err := s.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return val, nil
}

// CompareAndSwap implements Store.
func (s *RedisStore) CompareAndSwap(ctx context.Context, key string, oldVal, newVal []byte, ttl time.Duration) (bool, error) {
	oldPresent := "1"
	if oldVal == nil {
		oldPresent = "0"
	}
	res, err := s.client.Eval(ctx, casScript, []string{key},
		oldPresent, oldVal, newVal, ttl.Milliseconds(),
	).Result()
	if err != nil {
		return false, err
	}
	n, err := toInt64(res)
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// Ping implements Store.
func (s *RedisStore) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

// Close implements Store.
func (s *RedisStore) Close() error {
	return s.client.Close()
}

func toInt64(v any) (int64, error) {
	n, ok := v.(int64)
	if !ok {
		return 0, errors.New("store: unexpected reply type from redis script")
	}
	return n, nil
}
