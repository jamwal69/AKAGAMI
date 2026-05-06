"""
ReconForge Event Bus — Pub/Sub for Streaming DAG execution.
Replaces the static TaskCoordinationGraph with an event-driven model.
"""
import asyncio
from typing import Callable, Coroutine, Any
from pydantic import BaseModel

from reconforge.utils.logger import get_logger

logger = get_logger("event_bus")


class Event(BaseModel):
    """Base event type emitted by tools and agents."""
    name: str
    data: dict[str, Any]


class EventBus:
    """
    Asynchronous pub/sub event bus.
    Agents publish findings. The orchestrator subscribes to specific events
    to spawn downstream tasks dynamically.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callable[[Event], Coroutine]]] = {}
        self._queue: asyncio.Queue[Event] = asyncio.Queue()
        self._worker_task: asyncio.Task | None = None
        self._running = False

    def subscribe(self, event_name: str, handler: Callable[[Event], Coroutine]) -> None:
        """Register a handler for a specific event type."""
        if event_name not in self._subscribers:
            self._subscribers[event_name] = []
        self._subscribers[event_name].append(handler)
        logger.debug(f"Subscribed handler {handler.__name__} to event '{event_name}'")

    async def publish(self, event: Event) -> None:
        """Publish an event to the bus."""
        await self._queue.put(event)
        logger.debug(f"Published event '{event.name}'")

    async def _worker(self) -> None:
        """Background worker that routes events to subscribers."""
        self._running = True
        logger.info("EventBus worker started")
        while self._running:
            try:
                event = await self._queue.get()
            except asyncio.CancelledError:
                break
                
            handlers = self._subscribers.get(event.name, [])
            if not handlers:
                self._queue.task_done()
                continue

            for handler in handlers:
                try:
                    await handler(event)
                except Exception as e:
                    logger.error(f"Error in event handler {handler.__name__} for {event.name}: {e}")
            
            self._queue.task_done()

    def start(self) -> None:
        """Start the background event router."""
        if self._worker_task is None:
            self._worker_task = asyncio.create_task(self._worker())

    async def stop(self) -> None:
        """Stop the event router gracefully."""
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None
        logger.info("EventBus worker stopped")

    async def join(self) -> None:
        """Wait for all events in the queue to be processed."""
        await self._queue.join()
