import Foundation
import Testing

@testable import AuthenticationKit

@Suite("Rate limiting")
struct RateLimiterTests {

    @Test("A bucket allows a burst up to its capacity, then denies")
    func burstThenDeny() async {
        let clock = TestClock()
        let limiter = RateLimiter(now: clock.provider)
        let limit = RateLimiter.Limit(capacity: 3, refillPerSecond: 1)

        for _ in 0..<3 {
            #expect(await limiter.consume(key: "caller", limit: limit).isAllowed)
        }
        let denied = await limiter.consume(key: "caller", limit: limit)
        #expect(!denied.isAllowed)
        #expect(denied.retryAfter >= 1)
    }

    @Test("Buckets refill over time")
    func refill() async {
        let clock = TestClock()
        let limiter = RateLimiter(now: clock.provider)
        let limit = RateLimiter.Limit(capacity: 2, refillPerSecond: 0.5)

        _ = await limiter.consume(key: "caller", limit: limit)
        _ = await limiter.consume(key: "caller", limit: limit)
        #expect(!(await limiter.consume(key: "caller", limit: limit)).isAllowed)

        // 0.5 permits/second means two seconds buys exactly one more call.
        clock.advance(by: 2)
        #expect(await limiter.consume(key: "caller", limit: limit).isAllowed)
        #expect(!(await limiter.consume(key: "caller", limit: limit)).isAllowed)
    }

    @Test("Buckets never refill past capacity")
    func capacityCeiling() async {
        let clock = TestClock()
        let limiter = RateLimiter(now: clock.provider)
        let limit = RateLimiter.Limit(capacity: 2, refillPerSecond: 10)

        _ = await limiter.consume(key: "caller", limit: limit)
        clock.advance(by: 3600)

        #expect(await limiter.consume(key: "caller", limit: limit).isAllowed)
        #expect(await limiter.consume(key: "caller", limit: limit).isAllowed)
        #expect(!(await limiter.consume(key: "caller", limit: limit)).isAllowed)
    }

    @Test("Callers have independent buckets")
    func isolation() async {
        let limiter = RateLimiter()
        let limit = RateLimiter.Limit(capacity: 1, refillPerSecond: 0.1)

        #expect(await limiter.consume(key: "alice", limit: limit).isAllowed)
        #expect(!(await limiter.consume(key: "alice", limit: limit)).isAllowed)
        #expect(await limiter.consume(key: "bob", limit: limit).isAllowed)
    }
}
