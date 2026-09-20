import Foundation
import Logging
import MCP

@preconcurrency import NIOCore
@preconcurrency import NIOHTTP1

/// Translates between NIO's HTTP types and the transport's framework-agnostic
/// `HTTPRequest`/`HTTPResponse`.
///
/// Deliberately contains no MCP logic: everything is delegated to ``MCPHTTPHost``,
/// so swapping NIO for another HTTP server would mean replacing only this file.
final class NIOAdapter: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    /// Refuses request bodies larger than this, so a single connection cannot
    /// exhaust memory before the JSON layer ever sees the payload.
    private static let maximumBodyBytes = 4 * 1024 * 1024

    private let host: MCPHTTPHost

    private struct RequestState {
        var head: HTTPRequestHead
        var body: ByteBuffer
        var isOversized: Bool
    }

    private var state: RequestState?

    init(host: MCPHTTPHost) {
        self.host = host
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head):
            state = RequestState(
                head: head,
                body: context.channel.allocator.buffer(capacity: 0),
                isOversized: false)

        case .body(var buffer):
            guard state != nil else { return }
            if state!.body.readableBytes + buffer.readableBytes > Self.maximumBodyBytes {
                // Stop accumulating, but keep reading to end so the connection can
                // be answered cleanly rather than reset.
                state!.isOversized = true
                state!.body.clear()
                return
            }
            state!.body.writeBuffer(&buffer)

        case .end:
            guard let finished = state else { return }
            state = nil

            nonisolated(unsafe) let channelContext = context
            Task {
                await self.dispatch(finished, context: channelContext)
            }
        }
    }

    // MARK: - Dispatch

    private func dispatch(_ state: RequestState, context: ChannelHandlerContext) async {
        guard !state.isOversized else {
            await write(
                .error(statusCode: 413, .invalidRequest("Request body is too large")),
                version: state.head.version,
                context: context)
            return
        }

        let response = await host.handle(makeRequest(from: state))
        await write(response, version: state.head.version, context: context)
    }

    private func makeRequest(from state: RequestState) -> HTTPRequest {
        // RFC 7230 §3.2.2: repeated headers combine into a comma-separated list.
        var headers: [String: String] = [:]
        for (name, value) in state.head.headers {
            headers[name] = headers[name].map { "\($0), \(value)" } ?? value
        }

        let body: Data? =
            state.body.readableBytes > 0
            ? Data(state.body.getBytes(at: 0, length: state.body.readableBytes) ?? [])
            : nil

        let path = String(state.head.uri.split(separator: "?").first ?? Substring(state.head.uri))

        return HTTPRequest(
            method: state.head.method.rawValue,
            headers: headers,
            body: body,
            path: path)
    }

    // MARK: - Writing

    private func write(
        _ response: HTTPResponse,
        version: HTTPVersion,
        context: ChannelHandlerContext
    ) async {
        nonisolated(unsafe) let channelContext = context
        let eventLoop = channelContext.eventLoop

        // Built here as a value so the event-loop closures capture something
        // `Sendable` rather than a local function that closes over the context.
        var head = HTTPResponseHead(
            version: version,
            status: HTTPResponseStatus(statusCode: response.statusCode))
        for (name, value) in response.headers {
            head.headers.add(name: name, value: value)
        }
        let responseHead = head

        switch response {
        case .stream(let stream, _):
            // Server-sent events: head first, then each chunk as it arrives.
            eventLoop.execute {
                channelContext.write(self.wrapOutboundOut(.head(responseHead)), promise: nil)
                channelContext.flush()
            }

            do {
                for try await chunk in stream {
                    eventLoop.execute {
                        var buffer = channelContext.channel.allocator.buffer(capacity: chunk.count)
                        buffer.writeBytes(chunk)
                        channelContext.writeAndFlush(
                            self.wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
                    }
                }
            } catch {
                // The stream ended early; close the response below either way.
            }

            eventLoop.execute {
                channelContext.writeAndFlush(self.wrapOutboundOut(.end(nil)), promise: nil)
            }

        default:
            let body = response.bodyData
            eventLoop.execute {
                channelContext.write(self.wrapOutboundOut(.head(responseHead)), promise: nil)
                if let body {
                    var buffer = channelContext.channel.allocator.buffer(capacity: body.count)
                    buffer.writeBytes(body)
                    channelContext.write(
                        self.wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
                }
                channelContext.writeAndFlush(self.wrapOutboundOut(.end(nil)), promise: nil)
            }
        }
    }
}
