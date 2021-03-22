/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 *
 *   Copyright (C) 2020 John Crispin <john@phrozen.org> 
 */

#include "ucentral.h"

struct ucentral_task {
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

	t->task->run(t->uuid);
	exit(1);
}

static const struct runqueue_task_type task_type = {
	.run = task_run_cb,
	.cancel = runqueue_process_cancel_cb,
	.kill = runqueue_process_kill_cb,
};

static void
task_complete(struct runqueue *q, struct runqueue_task *task)
{
	struct ucentral_task *t = container_of(task, struct ucentral_task, proc.task);
	t->task->complete(t->task, t->uuid, t->id, t->ret);
	free(t);
}

static void
task_delay(struct uloop_timeout *delay)
{
	struct ucentral_task *t = container_of(delay, struct ucentral_task, delay);
	runqueue_task_add(&runqueue, &t->proc.task, false);
}

void
task_run(struct task *task, time_t uuid, uint32_t id)
{
	struct ucentral_task *t = calloc(1, sizeof(*t));

	t->uuid = uuid;
	t->id = id;
	t->task = task;
	t->proc.task.type = &task_type;
	t->proc.task.run_timeout = task->run_time * 1000;
	t->proc.task.complete = task_complete;

	if (task->delay) {
		t->delay.cb = task_delay;
		uloop_timeout_set(&t->delay, task->delay * 1000);
	} else {
		runqueue_task_add(&runqueue, &t->proc.task, false);
	}
}
