import Foundation

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

/// An advisory, cross-process exclusive lock over a lock file.
///
/// Needed because the credential store is shared by every invocation of this
/// binary. Two MCP servers starting at once — or a server and a `auth login` —
/// would otherwise interleave a read-refresh-write cycle, and the loser would
/// persist a refresh token the provider had already rotated away, locking the
/// user out. `flock` serialises the whole cycle instead.
final class FileLock {
    private let descriptor: Int32

    init(path: String) throws {
        descriptor = open(path, O_CREAT | O_RDWR | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else {
            throw SecretStoreError.unavailable(
                reason: "could not open the lock file at \(path): \(String(cString: strerror(errno)))")
        }
    }

    deinit {
        close(descriptor)
    }

    /// Runs `body` while holding the lock, waiting up to `timeout` to acquire it.
    ///
    /// Polls a non-blocking `flock` rather than blocking outright, so a stale
    /// holder cannot wedge the process forever.
    func withExclusiveLock<T>(timeout: TimeInterval = 10, _ body: () throws -> T) throws -> T {
        let deadline = Date().addingTimeInterval(timeout)

        while flock(descriptor, LOCK_EX | LOCK_NB) != 0 {
            guard errno == EWOULDBLOCK else {
                throw SecretStoreError.unavailable(
                    reason: "could not lock the credential store: \(String(cString: strerror(errno)))")
            }
            guard Date() < deadline else {
                throw SecretStoreError.unavailable(
                    reason:
                        "another process has held the credential store for more than "
                        + "\(Int(timeout))s; if nothing else is running, remove the lock file")
            }
            usleep(25_000)
        }

        defer { flock(descriptor, LOCK_UN) }
        return try body()
    }
}
