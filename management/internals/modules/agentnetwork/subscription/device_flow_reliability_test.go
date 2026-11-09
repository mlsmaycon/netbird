package subscription

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cachestore "github.com/eko/gocache/lib/v4/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbcache "github.com/netbirdio/netbird/management/server/cache"
)

// deviceFlowCache keeps real cache behavior except for explicit race and
// failure points, so the tests exercise the same atomic operations as replicas.
type deviceFlowCache struct {
	nbcache.Store
	blockNextSlot    atomic.Bool
	resultReadError  atomic.Bool
	resultWriteError atomic.Bool
	redemptionError  atomic.Bool
	permitError      atomic.Bool
	slotReached      chan struct{}
	allowSlot        chan struct{}
}

func (c *deviceFlowCache) GetDel(ctx context.Context, key string) (string, bool, error) {
	if strings.HasSuffix(key, devicePermitSuffix) && c.permitError.Load() {
		return "", false, errors.New("permit cache unavailable")
	}
	return c.Store.GetDel(ctx, key)
}

func (c *deviceFlowCache) SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	if strings.HasSuffix(key, devicePollSuffix) && c.blockNextSlot.CompareAndSwap(true, false) {
		close(c.slotReached)
		select {
		case <-c.allowSlot:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	if strings.HasSuffix(key, deviceRedemptionSuffix) && c.redemptionError.Load() {
		return false, errors.New("redemption cache unavailable")
	}
	return c.Store.SetNX(ctx, key, value, ttl)
}

func (c *deviceFlowCache) Get(ctx context.Context, key any) (any, error) {
	if value, ok := key.(string); ok && strings.HasSuffix(value, ":result") && c.resultReadError.Load() {
		return nil, errors.New("result cache unavailable")
	}
	return c.Store.Get(ctx, key)
}

func (c *deviceFlowCache) Set(ctx context.Context, key, value any, options ...cachestore.Option) error {
	if name, ok := key.(string); ok && strings.HasSuffix(name, ":result") && c.resultWriteError.Load() {
		return errors.New("result cache unavailable")
	}
	return c.Store.Set(ctx, key, value, options...)
}

func TestDeviceFlow_DelayedPollRechecksSharedState(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := "linked result"
		if pending {
			name = "advanced interval"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			issuer := newFakeIssuer(t)
			if pending {
				issuer.pendingPolls = 1
			}
			store := newTestStore(t, true)
			cache := newTestCache(t)
			delayedCache := &deviceFlowCache{Store: cache, slotReached: make(chan struct{}), allowSlot: make(chan struct{})}
			delayedCache.blockNextSlot.Store(true)
			first := NewService(store, delayedCache, nil)
			second := NewService(store, cache, nil)
			now := time.Now().UTC()
			first.now = func() time.Time { return now }
			second.now = first.now
			flow, err := first.StartLink(ctx, testKey, testAdmin, issuer.entry())
			require.NoError(t, err)
			now = now.Add(2 * time.Second)
			type outcome struct {
				flow *Flow
				err  error
			}
			completed := make(chan outcome, 1)
			go func() {
				result, err := first.PollLink(ctx, testKey, testAdmin, flow.ID, issuer.entry())
				completed <- outcome{flow: result, err: err}
			}()
			select {
			case <-delayedCache.slotReached:
			case <-ctx.Done():
				t.Fatal("the delayed poll did not reach its slot")
			}
			result, err := second.PollLink(ctx, testKey, testAdmin, flow.ID, issuer.entry())
			require.NoError(t, err)
			// Simulate the delayed request resuming after its predecessor's slot expired.
			require.NoError(t, cache.Delete(ctx, flowKeyPrefix+flow.ID+devicePollSuffix))
			close(delayedCache.allowSlot)
			var delayed outcome
			select {
			case delayed = <-completed:
			case <-ctx.Done():
				t.Fatal("the delayed poll did not finish")
			}
			require.NoError(t, delayed.err)
			assert.Equal(t, result.Status, delayed.flow.Status)
			assert.False(t, delayed.flow.JustLinked, "only the poll that writes credentials may emit a linking event")
			issuer.mu.Lock()
			generation := issuer.generation
			issuer.mu.Unlock()
			if pending {
				assert.Equal(t, FlowPending, delayed.flow.Status)
				assert.Zero(t, generation, "a stale poll must respect the newly advanced interval")
			} else {
				assert.Equal(t, FlowLinked, delayed.flow.Status)
				assert.Equal(t, 1, generation, "a stale poll must not exchange a redeemed grant")
			}
		})
	}
}

func TestDeviceFlow_TerminalOutcomeAndGuardOutliveMetadata(t *testing.T) {
	ctx := context.Background()
	issuer := newFakeIssuer(t)
	cache := newTestCache(t)
	svc := NewService(newTestStore(t, true), cache, nil)
	now := time.Now().UTC()
	svc.now = func() time.Time { return now }
	flow, err := svc.StartLink(ctx, testKey, testAdmin, issuer.entry())
	require.NoError(t, err)
	now = now.Add(2 * time.Second)
	linked, err := svc.PollLink(ctx, testKey, testAdmin, flow.ID, issuer.entry())
	require.NoError(t, err)
	assert.Equal(t, FlowLinked, linked.Status)
	_, metadataTTL, err := cache.GetWithTTL(ctx, flowKeyPrefix+flow.ID)
	require.NoError(t, err)
	_, resultTTL, err := cache.GetWithTTL(ctx, flowKeyPrefix+flow.ID+":result")
	require.NoError(t, err)
	_, redemptionTTL, err := cache.GetWithTTL(ctx, flowKeyPrefix+flow.ID+deviceRedemptionSuffix)
	require.NoError(t, err)
	assert.Greater(t, resultTTL, flowResultTTL, "an early result must remain terminal until the original flow expires")
	assert.InDelta(t, metadataTTL.Seconds(), resultTTL.Seconds(), 0.1)
	assert.InDelta(t, metadataTTL.Seconds(), redemptionTTL.Seconds(), 0.1)

	// Even losing the terminal result cannot restore the right to redeem.
	require.NoError(t, cache.Delete(ctx, flowKeyPrefix+flow.ID+":result"))
	now = now.Add(deviceRedemptionTimeout + time.Second)
	failed, err := svc.PollLink(ctx, testKey, testAdmin, flow.ID, issuer.entry())
	require.NoError(t, err)
	assert.Equal(t, FlowFailed, failed.Status, "a missing outcome requires restarting, never reusing the grant")
	issuer.mu.Lock()
	assert.Equal(t, 1, issuer.generation)
	issuer.mu.Unlock()
}

func TestDeviceFlow_OverlappingApprovalsExchangeOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	issuer := newFakeIssuer(t)
	firstPoll := make(chan struct{})
	finishPoll := make(chan struct{})
	var polls atomic.Int32
	handler := issuer.srv.Config.Handler
	issuer.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/accounts/deviceauth/token" && polls.Add(1) == 1 {
			close(firstPoll)
			select {
			case <-finishPoll:
			case <-ctx.Done():
				return
			}
		}
		handler.ServeHTTP(w, r)
	})
	store := newTestStore(t, true)
	cache := newTestCache(t)
	first := NewService(store, cache, nil)
	second := NewService(store, cache, nil)
	now := time.Now().UTC()
	first.now = func() time.Time { return now }
	second.now = first.now
	flow, err := first.StartLink(ctx, testKey, testAdmin, issuer.entry())
	require.NoError(t, err)
	now = now.Add(2 * time.Second)
	type outcome struct {
		flow *Flow
		err  error
	}
	finished := make(chan outcome, 1)
	go func() {
		result, err := first.PollLink(ctx, testKey, testAdmin, flow.ID, issuer.entry())
		finished <- outcome{flow: result, err: err}
	}()
	select {
	case <-firstPoll:
	case <-ctx.Done():
		t.Fatal("first replica did not start its approval poll")
	}
	// A slow approval poll may outlive the interval, allowing another replica to poll.
	require.NoError(t, cache.Delete(ctx, flowKeyPrefix+flow.ID+devicePollSuffix))
	linked, err := second.PollLink(ctx, testKey, testAdmin, flow.ID, issuer.entry())
	close(finishPoll)
	require.NoError(t, err)
	assert.Equal(t, FlowLinked, linked.Status)
	select {
	case delayed := <-finished:
		require.NoError(t, delayed.err)
		assert.Equal(t, FlowLinked, delayed.flow.Status)
		assert.False(t, delayed.flow.JustLinked, "a late approval must observe the first redemption's result")
	case <-ctx.Done():
		t.Fatal("the delayed approval poll did not finish")
	}
	issuer.mu.Lock()
	assert.Equal(t, 1, issuer.generation, "overlapping approvals must exchange the grant once")
	issuer.mu.Unlock()
}

func TestDeviceFlow_MissingExchangePermitFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name         string
		completeOnce bool
		consumeError bool
	}{
		{name: "terminal result and redemption marker lost", completeOnce: true},
		{name: "legacy or evicted permit"},
		{name: "permit consume error", consumeError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			issuer := newFakeIssuer(t)
			cache := &deviceFlowCache{Store: newTestCache(t)}
			svc := NewService(newTestStore(t, true), cache, nil)
			now := time.Now().UTC()
			svc.now = func() time.Time { return now }
			flow, err := svc.StartLink(ctx, testKey, testAdmin, issuer.entry())
			require.NoError(t, err)
			now = now.Add(2 * time.Second)
			if tc.completeOnce {
				linked, err := svc.PollLink(ctx, testKey, testAdmin, flow.ID, issuer.entry())
				require.NoError(t, err)
				assert.Equal(t, FlowLinked, linked.Status)
				for _, suffix := range []string{":result", deviceRedemptionSuffix, devicePollSuffix} {
					require.NoError(t, cache.Delete(ctx, flowKeyPrefix+flow.ID+suffix))
				}
			} else if !tc.consumeError {
				require.NoError(t, cache.Delete(ctx, flowKeyPrefix+flow.ID+devicePermitSuffix))
			}
			cache.permitError.Store(tc.consumeError)
			result, err := svc.PollLink(ctx, testKey, testAdmin, flow.ID, issuer.entry())
			if tc.consumeError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, FlowFailed, result.Status)
			}
			_, resultErr := cache.Get(ctx, flowKeyPrefix+flow.ID+":result")
			assert.Error(t, resultErr, "a failed permit claim must not overwrite another owner's eventual outcome")
			issuer.mu.Lock()
			generation := issuer.generation
			issuer.mu.Unlock()
			if tc.completeOnce {
				assert.Equal(t, 1, generation, "losing both cached status keys must not allow replay")
			} else {
				assert.Zero(t, generation, "a missing or unreadable permit must prevent exchange")
			}
		})
	}
}

func TestDeviceFlow_CacheFailuresCannotReplay(t *testing.T) {
	for _, failure := range []string{"read result", "claim redemption", "write result"} {
		t.Run(failure, func(t *testing.T) {
			ctx := context.Background()
			issuer := newFakeIssuer(t)
			cache := &deviceFlowCache{Store: newTestCache(t)}
			svc := NewService(newTestStore(t, true), cache, nil)
			now := time.Now().UTC()
			svc.now = func() time.Time { return now }
			flow, err := svc.StartLink(ctx, testKey, testAdmin, issuer.entry())
			require.NoError(t, err)
			now = now.Add(2 * time.Second)
			cache.resultReadError.Store(failure == "read result")
			cache.redemptionError.Store(failure == "claim redemption")
			cache.resultWriteError.Store(failure == "write result")
			result, err := svc.PollLink(ctx, testKey, testAdmin, flow.ID, issuer.entry())
			if failure == "write result" {
				require.NoError(t, err)
				assert.Equal(t, FlowLinked, result.Status)
			} else {
				require.Error(t, err, "cache uncertainty must fail closed before token exchange")
			}
			issuer.mu.Lock()
			generation := issuer.generation
			issuer.mu.Unlock()
			if failure == "write result" {
				assert.Equal(t, 1, generation)
			} else {
				assert.Zero(t, generation)
			}
			cache.resultReadError.Store(false)
			cache.redemptionError.Store(false)
			cache.resultWriteError.Store(false)
			require.NoError(t, cache.Delete(ctx, flowKeyPrefix+flow.ID+devicePollSuffix))
			now = now.Add(deviceRedemptionTimeout + time.Second)
			result, err = svc.PollLink(ctx, testKey, testAdmin, flow.ID, issuer.entry())
			require.NoError(t, err)
			if failure == "write result" {
				assert.Equal(t, FlowFailed, result.Status, "a possibly redeemed grant cannot be retried")
			} else {
				assert.Equal(t, FlowLinked, result.Status, "cache recovery may complete a grant never exchanged")
			}
			issuer.mu.Lock()
			assert.Equal(t, 1, issuer.generation, "every grant is exchanged at most once")
			issuer.mu.Unlock()
		})
	}
}

func TestDeviceFlow_ClientCancellationPreservesRedeemedTokens(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	issuer := newFakeIssuer(t)
	handler := issuer.srv.Config.Handler
	issuer.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			cancel()
		}
		handler.ServeHTTP(w, r)
	})
	store := newTestStore(t, true)
	svc := NewService(store, newTestCache(t), nil)
	now := time.Now().UTC()
	svc.now = func() time.Time { return now }
	flow, err := svc.StartLink(ctx, testKey, testAdmin, issuer.entry())
	require.NoError(t, err)
	now = now.Add(2 * time.Second)
	linked, err := svc.PollLink(ctx, testKey, testAdmin, flow.ID, issuer.entry())
	require.NoError(t, err)
	assert.ErrorIs(t, ctx.Err(), context.Canceled)
	assert.Equal(t, FlowLinked, linked.Status, "request cancellation must not lose a token already being redeemed")
	cred, err := store.GetAgentNetworkProviderCredential(context.Background(), testKey.AccountID, testKey.ProviderID)
	require.NoError(t, err)
	assert.Equal(t, "rt-1", cred.RefreshToken)
	polled, err := svc.PollLink(context.Background(), testKey, testAdmin, flow.ID, issuer.entry())
	require.NoError(t, err)
	assert.Equal(t, FlowLinked, polled.Status, "the completed outcome must survive the canceled request")
}
