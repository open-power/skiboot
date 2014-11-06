#include <timer.h>
#include <timebase.h>
#include <lock.h>

#ifdef __TEST__
#define this_cpu()	((void *)-1)
#define cpu_relax()
#else
#include <cpu.h>
#endif

static struct lock timer_lock = LOCK_UNLOCKED;
static LIST_HEAD(timer_list);

void init_timer(struct timer *t, timer_func_t expiry, void *data)
{
	t->link.next = t->link.prev = NULL;
	t->target = 0;
	t->expiry = expiry;
	t->user_data = data;
	t->running = NULL;
}

static void __remove_timer(struct timer *t)
{
	list_del(&t->link);
	t->link.next = t->link.prev = NULL;
}

static void __sync_timer(struct timer *t)
{
	sync();

	/* Guard against re-entrancy */
	assert(t->running != this_cpu());

	while (t->running) {
		unlock(&timer_lock);
		cpu_relax();
		/* Should we call the pollers here ? */
		lock(&timer_lock);
	}
}

void sync_timer(struct timer *t)
{
	lock(&timer_lock);
	__sync_timer(t);
	unlock(&timer_lock);
}

void cancel_timer(struct timer *t)
{
	lock(&timer_lock);
	__sync_timer(t);
	if (t->link.next)
		__remove_timer(t);
	unlock(&timer_lock);
}

void cancel_timer_async(struct timer *t)
{
	lock(&timer_lock);
	if (t->link.next)
		__remove_timer(t);
	unlock(&timer_lock);
}

void schedule_timer_at(struct timer *t, uint64_t when)
{
	struct timer *lt;

	lock(&timer_lock);
	if (t->link.next)
		__remove_timer(t);
	t->target = when;
	list_for_each(&timer_list, lt, link) {
		if (when < lt->target) {
			list_add_before(&timer_list, &t->link, &lt->link);
			unlock(&timer_lock);
			return;
		}
	}
	list_add_tail(&timer_list, &t->link);
	unlock(&timer_lock);
}

void schedule_timer(struct timer *t, uint64_t how_long)
{
	schedule_timer_at(t, mftb() + how_long);
}

void check_timers(void)
{
	struct timer *t;
	uint64_t now = mftb();

	/* Lockless "peek", a bit racy but shouldn't be a problem */
	t = list_top(&timer_list, struct timer, link);
	if (!t || t->target > now)
		return;

	/* Take lock and try again */
	lock(&timer_lock);
	for (;;) {
		t = list_top(&timer_list, struct timer, link);
		now = mftb();

		/* Top of list not expired ? that's it ... */
		if (!t || t->target > now)
			break;

		/* Top of list still running, we have to delay handling
		 * it. For now just skip until the next poll, when we have
		 * SLW interrupts, we'll probably want to trip another one
		 * ASAP
		 */
		if (t->running)
			break;

		/* Allright, first remove it and mark it running */
		__remove_timer(t);
		t->running = this_cpu();

		/* Now we can unlock and call it's expiry */
		unlock(&timer_lock);
		t->expiry(t, t->user_data);

		/* Re-lock and mark not running */
		lock(&timer_lock);
		t->running = NULL;
	}
	unlock(&timer_lock);
}
