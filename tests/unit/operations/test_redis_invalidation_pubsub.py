from collections import deque
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from redis.exceptions import RedisError

from pyiamkit.operations import (
    AuthorizationCacheInvalidationHandler,
    CacheNamespace,
    InvalidationEvent,
    InvalidationHandler,
    InvalidationKind,
    OperationalJsonCodec,
    RedisKeyspace,
    StateVersion,
)
from pyiamkit.operations.adapters.redis import (
    RedisInvalidationPublisher,
    RedisInvalidationSubscriber,
)
from pyiamkit.tenancy import TenantId

NOW = datetime(2026, 10, 1, 10, 30, tzinfo=UTC)


class FakePublisher:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.messages: list[tuple[str, bytes]] = []

    def publish(self, channel: str, message: bytes) -> object:
        if self.fail:
            raise RedisError("redis unavailable")
        self.messages.append((channel, message))
        return 1


class FakePubSub:
    def __init__(self, *, fail_subscribe: bool = False, fail_poll: bool = False) -> None:
        self.fail_subscribe = fail_subscribe
        self.fail_poll = fail_poll
        self.channels: list[str] = []
        self.messages: deque[object] = deque()

    def subscribe(self, *channels: str) -> object:
        if self.fail_subscribe:
            raise RedisError("redis unavailable")
        self.channels.extend(channels)
        return None

    def get_message(
        self,
        *,
        ignore_subscribe_messages: bool,
        timeout: float,
    ) -> object | None:
        del ignore_subscribe_messages, timeout
        if self.fail_poll:
            raise RedisError("redis unavailable")
        return self.messages.popleft() if self.messages else None


class RecordingHandler(InvalidationHandler):
    def __init__(self, *, accept: bool = True) -> None:
        self.accept = accept
        self.events: list[InvalidationEvent] = []

    def handle(self, event: InvalidationEvent) -> bool:
        self.events.append(event)
        return self.accept


class FakeCache:
    def __init__(self) -> None:
        self.clears = 0

    def get(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        return None

    def put(self, entry: object) -> None:
        del entry

    def delete(self, key: object) -> None:
        del key

    def clear(self) -> None:
        self.clears += 1


def _event(
    *,
    version: int,
    target_id: str = "subject-1",
    kind: InvalidationKind = InvalidationKind.AUTHORIZATION,
    event_id=None,
) -> InvalidationEvent:
    return InvalidationEvent(
        event_id=event_id or uuid4(),
        kind=kind,
        target_id=target_id,
        tenant_id=TenantId.new(),
        state_version=StateVersion(version),
        occurred_at=NOW,
    )


def _subscriber(
    pubsub: FakePubSub,
    handler: InvalidationHandler,
    *,
    max_seen_events: int = 10,
) -> RedisInvalidationSubscriber:
    return RedisInvalidationSubscriber(
        pubsub,
        keyspace=RedisKeyspace(CacheNamespace("billing-api", "test")),
        handler=handler,
        max_seen_events=max_seen_events,
    )


def test_redis_invalidation_publisher_uses_versioned_channel_and_codec() -> None:
    client = FakePublisher()
    keyspace = RedisKeyspace(CacheNamespace("billing-api", "test"))
    publisher = RedisInvalidationPublisher(client, keyspace=keyspace)
    event = _event(version=4)

    publisher.publish(event)

    assert len(client.messages) == 1
    channel, payload = client.messages[0]
    assert channel == keyspace.invalidation_channel
    assert OperationalJsonCodec().decode_invalidation_event(payload) == event


def test_redis_invalidation_publish_failure_is_best_effort() -> None:
    publisher = RedisInvalidationPublisher(
        FakePublisher(fail=True),
        keyspace=RedisKeyspace(CacheNamespace("billing-api", "test")),
    )

    publisher.publish(_event(version=1))


def test_subscriber_subscribes_and_processes_message() -> None:
    pubsub = FakePubSub()
    handler = RecordingHandler()
    subscriber = _subscriber(pubsub, handler)
    event = _event(version=2)
    pubsub.messages.append(
        {
            "type": "message",
            "data": OperationalJsonCodec().encode_invalidation_event(event),
        }
    )

    assert subscriber.subscribe() is True
    assert subscriber.poll() is True
    assert handler.events == [event]


def test_subscriber_rejects_duplicate_event_id() -> None:
    pubsub = FakePubSub()
    handler = RecordingHandler()
    subscriber = _subscriber(pubsub, handler)
    event = _event(version=2)

    assert subscriber.handle_event(event) is True
    assert subscriber.handle_event(event) is False
    assert handler.events == [event]


def test_subscriber_rejects_stale_or_equal_stream_version() -> None:
    pubsub = FakePubSub()
    handler = RecordingHandler()
    subscriber = _subscriber(pubsub, handler)
    current = _event(version=5)
    stale = _event(version=4, target_id=current.target_id)
    equal = _event(version=5, target_id=current.target_id)

    assert subscriber.handle_event(current) is True
    assert subscriber.handle_event(stale) is False
    assert subscriber.handle_event(equal) is False
    assert handler.events == [current]


def test_subscriber_accepts_newer_version_and_separate_kind_stream() -> None:
    pubsub = FakePubSub()
    handler = RecordingHandler()
    subscriber = _subscriber(pubsub, handler)
    first = _event(version=2)
    newer = _event(version=3, target_id=first.target_id)
    separate = _event(
        version=1,
        target_id=first.target_id,
        kind=InvalidationKind.AUTHENTICATION,
    )

    assert subscriber.handle_event(first) is True
    assert subscriber.handle_event(newer) is True
    assert subscriber.handle_event(separate) is True
    assert handler.events == [first, newer, separate]


@pytest.mark.parametrize(
    "message",
    [
        None,
        "not-a-message",
        {"type": "subscribe", "data": b"ignored"},
        {"type": "message", "data": "text"},
        {"type": "message", "data": b"{bad-json"},
    ],
)
def test_subscriber_rejects_non_data_or_corrupt_messages(message: object) -> None:
    pubsub = FakePubSub()
    handler = RecordingHandler()
    subscriber = _subscriber(pubsub, handler)
    if message is not None:
        pubsub.messages.append(message)

    assert subscriber.poll() is False
    assert handler.events == []


def test_subscriber_failures_do_not_become_state_authority() -> None:
    subscribe_failure = _subscriber(
        FakePubSub(fail_subscribe=True),
        RecordingHandler(),
    )
    poll_failure = _subscriber(
        FakePubSub(fail_poll=True),
        RecordingHandler(),
    )

    assert subscribe_failure.subscribe() is False
    assert poll_failure.poll() is False


def test_subscriber_does_not_mark_event_seen_when_handler_rejects_it() -> None:
    pubsub = FakePubSub()
    rejecting = RecordingHandler(accept=False)
    subscriber = _subscriber(pubsub, rejecting)
    event = _event(version=1)

    assert subscriber.handle_event(event) is False
    rejecting.accept = True
    assert subscriber.handle_event(event) is True
    assert rejecting.events == [event, event]


def test_subscriber_validates_configuration_and_timeout() -> None:
    pubsub = FakePubSub()
    handler = RecordingHandler()

    with pytest.raises(ValueError, match="greater than or equal to one"):
        _subscriber(pubsub, handler, max_seen_events=0)

    subscriber = _subscriber(pubsub, handler)
    with pytest.raises(ValueError, match="greater than or equal to zero"):
        subscriber.poll(timeout=-0.1)


def test_authorization_cache_invalidation_handler_clears_cache() -> None:
    cache = FakeCache()
    handler = AuthorizationCacheInvalidationHandler(cache)  # type: ignore[arg-type]

    assert handler.handle(_event(version=1)) is True
    assert cache.clears == 1
