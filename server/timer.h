typedef struct _timer *timer;

struct _timer {
	timer 	next;		/*  Next one to go off.. */
	timer   prev;		/*  Previous one to go off.. */
	/* time for timer to go off, absolute time */
	long 	alarm_time;
	/* procedure to call when timer goes off */
	void 	(*func)();
};

#define ALARM_TIME(x) ((x)->alarm_time)
#define ALARM_FUNC(x) ((x)->func)
#define ALARM_NEXT(x) ((x)->next)
#define ALARM_PREV(x) ((x)->prev)
#define TIMER_SIZE sizeof(struct _timer)

timer timer_set_rel(), timer_set_abs();
int reset_timer(), add_timer();
int suspend_timers(), restart_timers();
