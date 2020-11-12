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

#include "usync.h"

struct usync_task {
	time_t uuid;
	int ret;
	const struct task *task;
	struct runqueue_process proc;
};

static void
runqueue_proc_cb(struct uloop_process *p, int ret)
{
	struct runqueue_process *t = container_of(p, struct runqueue_process, proc);
	struct usync_task *u = container_of(t, struct usync_task, proc);

	u->ret = ret;

	runqueue_task_complete(&t->task);
}

static void task_run_cb(struct runqueue *q, struct runqueue_task *task)
{
	struct usync_task *t = container_of(task, struct usync_task, proc.task);
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
	struct usync_task *t = container_of(task, struct usync_task, proc.task);
	t->task->complete(t->ret);
	free(t);
}

void
task_run(const struct task *task, time_t uuid)
{
	struct usync_task *t = calloc(1, sizeof(*t));

	t->uuid = uuid;
	t->task = task;
	t->proc.task.type = &task_type;
	t->proc.task.run_timeout = task->run_time * 1000;
	t->proc.task.complete = task_complete;

	runqueue_task_add(&runqueue, &t->proc.task, false);
}
