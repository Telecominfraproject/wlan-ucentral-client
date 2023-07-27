/* SPDX-License-Identifier: BSD-3-Clause */

#include "ucentral.h"

struct ucentral_task {
	int admin;
	time_t uuid;
	uint32_t id;
	int ret;
	struct task *task;
	struct runqueue_process proc;
	struct uloop_timeout delay;
};

static void
runqueue_proc_cb(struct uloop_process *p, int ret)
{
	struct runqueue_process *t = container_of(p, struct runqueue_process, proc);
	struct ucentral_task *u = container_of(t, struct ucentral_task, proc);

	u->ret = ret;

	runqueue_task_complete(&t->task);
}

static void task_run_cb(struct runqueue *q, struct runqueue_task *task)
{
	struct ucentral_task *t = container_of(task, struct ucentral_task, proc.task);
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return;

	if (pid) {
		runqueue_process_add(q, &t->proc, pid);
		t->proc.proc.cb = runqueue_proc_cb;
		return;
	}

	t->task->run(t->uuid, t->id);
	free(t);
	exit(1);
}

static const struct runqueue_task_type task_type = {
	.run = task_run_cb,
	.cancel = runqueue_process_cancel_cb,
	.kill = runqueue_process_kill_cb,
};

static void
task_delay(struct uloop_timeout *delay)
{
	struct ucentral_task *t = container_of(delay, struct ucentral_task, delay);
	struct runqueue *r = t->admin ? &adminqueue : &runqueue;

	runqueue_task_add(r, &t->proc.task, false);
}

static void
task_complete(struct runqueue *q, struct runqueue_task *task)
{
	struct ucentral_task *t = container_of(task, struct ucentral_task, proc.task);
	t->task->cancelled = task->cancelled;
	t->task->complete(t->task, t->uuid, t->id, t->ret);
	if (t->task->periodic) {
		t->delay.cb = task_delay;
		uloop_timeout_set(&t->delay, t->task->periodic * 1000);
	} else {
		t->task->t = NULL;
		free(t);
	}
}

void
task_run(struct task *task, time_t uuid, uint32_t id, int admin)
{
	struct ucentral_task *t = calloc(1, sizeof(*t));
	struct runqueue *r = admin ? &adminqueue : &runqueue;

	t->admin = admin;
	t->uuid = uuid;
	t->id = id;
	t->task = task;
	t->proc.task.type = &task_type;
	t->proc.task.run_timeout = task->run_time * 1000;
	t->proc.task.cancel_type = SIGKILL;
	t->proc.task.complete = task_complete;
	task->t = t;

	if (task->delay) {
		t->delay.cb = task_delay;
		uloop_timeout_set(&t->delay, task->delay * 1000);
	} else {
		runqueue_task_add(r, &t->proc.task, false);
	}
}

void
task_config(struct task *task, time_t uuid, uint32_t id)
{
	struct ucentral_task *t = calloc(1, sizeof(*t));

	t->uuid = uuid;
	t->id = id;
	t->task = task;
	t->proc.task.type = &task_type;
	t->proc.task.run_timeout = task->run_time * 1000;
	t->proc.task.complete = task_complete;
	task->t = t;
	runqueue_task_add(&applyqueue, &t->proc.task, false);
}

void
task_telemetry(struct task *task, time_t uuid, uint32_t id)
{
	struct ucentral_task *t = calloc(1, sizeof(*t));

	t->uuid = uuid;
	t->id = id;
	t->task = task;
	t->proc.task.type = &task_type;
	t->proc.task.run_timeout = task->run_time * 1000;
	t->proc.task.complete = task_complete;
	task->t = t;
	runqueue_task_add(&telemetryqueue, &t->proc.task, false);
}

void
task_stop(struct task *task)
{
	if (!task->t)
		return;
	task->periodic = 0;
	uloop_timeout_cancel(&task->t->delay);
	runqueue_task_kill(&task->t->proc.task);
	if (task->t) {
		free(task->t);
		task->t = NULL;
	}
}
