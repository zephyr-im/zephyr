#ifndef mux_MODULE
#define mux_MODULE

/*
 * MAX_SOURCES - the greatest file descriptor # that can be waited on minus one
 *               This can not exceed FD_SETSIZE from <sys/types.h>.
 */

#define  MAX_SOURCES  32

/*
 * mux_end_loop_p - Setting this to true during a mux_loop causes the mux_loop
 *                  to be exited.
 */

extern int mux_end_loop_p;

/*
 *    void mux_init()
 *        Requires: mux_init has never been called before
 *        Effects: Initializes the mux module.  Must be called before
 *                 any other mux call.
 */

extern void mux_init();

/*
 *    void mux_add_input_source(int descriptior; void (*handler)(); void *arg)
 *        Requires: 0<=descriptor<MAX_SOURCES, mux_init has been called
 *        Modifies: Removes the previous input handler if any for descriptor
 *        Effects: Registers handler as the input handler for file descriptor
 *                 descriptor.  When mux_loop() is running and input is
 *                 available on descriptor, handler will be called with
 *                 argument arg.
 */

extern void mux_add_input_source();

/*
 *    void mux_loop()
 *        Requires: mux_init has been called.
 *        Effects: Loops until mux_end_loop_p becomes true.  (Sets
 *                 mux_end_loop_p false to start).  Whenever input is
 *                 available on an input source which has a registered
 *                 handler (see mux_add_input_source), that handler is
 *                 called with its argument.  It is guarenteed that if
 *                 input is available on a source, its respective input
 *                 handler, if any, will eventually be called.  No other
 *                 ordering guarentees are made.  When some signal handler
 *                 or input handler eventually sets mux_end_loop_p to
 *                 true, we return.
 */

extern void mux_loop();

#endif
