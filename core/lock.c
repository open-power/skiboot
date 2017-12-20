/* Copyright 2013-2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <skiboot.h>
#include <lock.h>
#include <assert.h>
#include <processor.h>
#include <cpu.h>
#include <console.h>

/* Set to bust locks. Note, this is initialized to true because our
 * lock debugging code is not going to work until we have the per
 * CPU data initialized
 */
bool bust_locks = true;

#ifdef DEBUG_LOCKS

static void lock_error(struct lock *l, const char *reason, uint16_t err)
{
	bust_locks = true;

	fprintf(stderr, "LOCK ERROR: %s @%p (state: 0x%016llx)\n",
		reason, l, l->lock_val);
	op_display(OP_FATAL, OP_MOD_LOCK, err);

	abort();
}

static void lock_check(struct lock *l)
{
	if ((l->lock_val & 1) && (l->lock_val >> 32) == this_cpu()->pir)
		lock_error(l, "Invalid recursive lock", 0);
}

static void unlock_check(struct lock *l)
{
	if (!(l->lock_val & 1))
		lock_error(l, "Unlocking unlocked lock", 1);

	if ((l->lock_val >> 32) != this_cpu()->pir)
		lock_error(l, "Unlocked non-owned lock", 2);

	if (l->in_con_path && this_cpu()->con_suspend == 0)
		lock_error(l, "Unlock con lock with console not suspended", 3);

	if (list_empty(&this_cpu()->locks_held))
		lock_error(l, "Releasing lock we don't hold depth", 4);
}

#else
static inline void lock_check(struct lock *l) { };
static inline void unlock_check(struct lock *l) { };
#endif /* DEBUG_LOCKS */

bool lock_held_by_me(struct lock *l)
{
	uint64_t pir64 = this_cpu()->pir;

	return l->lock_val == ((pir64 << 32) | 1);
}

static inline bool __try_lock(struct cpu_thread *cpu, struct lock *l)
{
	uint64_t val;

	val = cpu->pir;
	val <<= 32;
	val |= 1;

	barrier();
	if (__cmpxchg64(&l->lock_val, 0, val) == 0) {
		sync();
		return true;
	}
	return false;
}

bool try_lock_caller(struct lock *l, const char *owner)
{
	struct cpu_thread *cpu = this_cpu();

	if (bust_locks)
		return true;

	if (__try_lock(cpu, l)) {
		l->owner = owner;
		if (l->in_con_path)
			cpu->con_suspend++;
		list_add(&cpu->locks_held, &l->list);
		return true;
	}
	return false;
}

void lock_caller(struct lock *l, const char *owner)
{
	if (bust_locks)
		return;

	lock_check(l);
	for (;;) {
		if (try_lock_caller(l, owner))
			break;
		smt_lowest();
		while (l->lock_val)
			barrier();
		smt_medium();
	}
}

void unlock(struct lock *l)
{
	struct cpu_thread *cpu = this_cpu();

	if (bust_locks)
		return;

	unlock_check(l);

	l->owner = NULL;
	list_del(&l->list);
	lwsync();
	l->lock_val = 0;

	/* WARNING: On fast reboot, we can be reset right at that
	 * point, so the reset_lock in there cannot be in the con path
	 */
	if (l->in_con_path) {
		cpu->con_suspend--;
		if (cpu->con_suspend == 0 && cpu->con_need_flush)
			flush_console();
	}
}

bool lock_recursive_caller(struct lock *l, const char *caller)
{
	if (bust_locks)
		return false;

	if (lock_held_by_me(l))
		return false;

	lock_caller(l, caller);
	return true;
}

void init_locks(void)
{
	bust_locks = false;
}

void dump_locks_list(void)
{
	struct lock *l;

	prlog(PR_ERR, "Locks held:\n");
	list_for_each(&this_cpu()->locks_held, l, list)
		prlog(PR_ERR, "  %s\n", l->owner);
}

void drop_my_locks(bool warn)
{
	struct lock *l;

	while((l = list_pop(&this_cpu()->locks_held, struct lock, list)) != NULL) {
		if (warn)
			prlog(PR_ERR, "  %s\n", l->owner);
		unlock(l);
	}
}

