#ifndef _XSELECT_H_
#define _XSELECT_H_

extern void xselInitAtoms();
extern int xselGetOwnership();
extern int xselProcessSelection();
extern void xselOwnershipLost();
extern void xselGiveUpOwnership();

#endif
