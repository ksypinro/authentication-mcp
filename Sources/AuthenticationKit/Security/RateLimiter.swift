import Foundation

/// A token-bucket rate limiter, keyed by caller.
///
/// Two of the four tools are cheap, but `authenticate` drives network calls to an
/// authorization server and `updatedData` writes. A model in a retry loop can
/// otherwise hammer both. Buckets refill continuously rather than on a fixed
/// window, so a caller that backs off recovers smoothly instead of waiting for a
/// window boundary.
public actor RateLimiter {

    public struct Limit: Sendable, Equatable {
        /// Maximum burst size.
        public let capacity: Double
        /// Sustained rate, in permits per second.
        public let refillPerSecond: Double

        public init(capacity: Double, refillPerSecond: Double) {
            self.capacity = capacity
            self.refillPerSecond = refillPerSecond
        }

        /// Authorization is expensive and user-interactive: allow a small burst.
        public static let authentication = Limit(capacity: 5, refillPerSecond: 0.2)
        /// Checking on a sign-in — an existing session, or a pending flow by its
        /// `flow_id` — is cheap and paced by `wait_seconds`, so this only exists
        /// to stop a genuine spin loop. A client polling every second for the
        /// full five-minute device-code window never comes near it.
        public static let poll = Limit(capacity: 30, refillPerSecond: 2)
        /// Reads are cheap.
        public static let read = Limit(capacity: 60, refillPerSecond: 10)
        /// Writes are persisted and audited.
        public static let write = Limit(capacity: 30, refillPerSecond: 5)
    }

    /// The outcome of a rate-limit check.
    public struct Decision: Sendable, Equatable {
        public let isAllowed: Bool
        /// How long the caller should wait before retrying, when denied.
        public let retryAfter: TimeInterval
    }

    private struct Bucket {
        var tokens: Double
        var lastRefill: Date
    }

    private var buckets: [String: Bucket] = [:]
    private let now: @Sendable () -> Date

    public init(now: @escaping @Sendable () -> Date = { Date() }) {
        self.now = now
    }

    /// Takes one permit from `key`'s bucket, or reports how long to wait.
    public func consume(key: String, limit: Limit) -> Decision {
        let currentTime = now()
        var bucket = buckets[key] ?? Bucket(tokens: limit.capacity, lastRefill: currentTime)

        let elapsed = max(0, currentTime.timeIntervalSince(bucket.lastRefill))
        bucket.tokens = min(limit.capacity, bucket.tokens + elapsed * limit.refillPerSecond)
        bucket.lastRefill = currentTime

        guard bucket.tokens >= 1 else {
            let deficit = 1 - bucket.tokens
            let retryAfter = limit.refillPerSecond > 0 ? deficit / limit.refillPerSecond : .infinity
            buckets[key] = bucket
            return Decision(isAllowed: false, retryAfter: retryAfter.rounded(.up))
        }

        bucket.tokens -= 1
        buckets[key] = bucket
        return Decision(isAllowed: true, retryAfter: 0)
    }

    /// Drops buckets that have been full and idle, so the map cannot grow without bound.
    public func evictIdleBuckets(idleFor interval: TimeInterval = 3600) {
        let cutoff = now().addingTimeInterval(-interval)
        buckets = buckets.filter { $0.value.lastRefill > cutoff }
    }
}
