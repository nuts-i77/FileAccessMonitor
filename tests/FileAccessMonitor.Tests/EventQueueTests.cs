using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class EventQueueTests
{
    // Enqueue caps the queue by its Count; a SingleReader channel throws NotSupportedException there,
    // which stopped the Security log collector of 1.11.0-rc3 at its first event
    [Fact]
    public void Queue_can_tell_its_count()
    {
        var queue = EventLogCollectorService.NewQueue();
        Assert.True(queue.Reader.CanCount);
        queue.Writer.TryWrite(new EventLogCollectorService.RawEvent(4663, 1, null, []));
        Assert.Equal(1, queue.Reader.Count);
    }
}
