#ifndef _XMARK_H_
#define _XMARK_H_

#define XMARK_START_BOUND 0
#define XMARK_END_BOUND 1
#define XMARK_TEMP_BOUND 2

#define XMARK_REDRAW_CURRENT 1
#define XMARK_REDRAW_OLD 2
#define XMARK_REDRAW_START 3
#define XMARK_REDRAW_END 4

#define xmarkStart(gram,x,y) xmarkSetBound(gram,x,y,XMARK_START_BOUND)
#define xmarkEnd(gram,x,y) xmarkSetBound(gram,x,y,XMARK_END_BOUND)

extern int markblock[];
extern int markchar[];
extern int markpixel[];
extern x_gram *markgram;

#define STARTBLOCK (markblock[XMARK_START_BOUND])
#define ENDBLOCK   (markblock[XMARK_END_BOUND])
#define STARTCHAR  (markchar[XMARK_START_BOUND])
#define ENDCHAR    (markchar[XMARK_END_BOUND])
#define STARTPIXEL (markpixel[XMARK_START_BOUND])
#define ENDPIXEL   (markpixel[XMARK_END_BOUND])

extern int xmarkSecond();
extern void xmarkRedraw();
extern void xmarkClear();
extern int xmarkExtendFromStart();
extern int xmarkExtendFromNearest();

#endif
