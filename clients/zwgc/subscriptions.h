#ifndef subscriptions_MODULE
#define subscriptions_MODULE

extern int zwgc_active;

extern int puntable_address_p(/* string class, instance, recipient */);
extern void punt();
extern void unpunt();
extern void zwgc_shutdown();
extern void zwgc_startup();

#endif
