/* RV64 base signal frame; Linux asserts these offsets against its UAPI. */
#ifndef NACRE_SIGNAL_ABI_H
#define NACRE_SIGNAL_ABI_H
#define NACRE_GATE_SIGNAL 0x1002
#define NACRE_SIGNAL_FETCH 0
#define NACRE_SIGNAL_DONE 1
#define NACRE_SIGNAL_RETURN 2
#define NACRE_SIGNAL_BAD 3
#define NACRE_SIGNAL_FRAME_SIZE 1088UL
#define NACRE_SIGNAL_UC 128UL
#define NACRE_SIGNAL_REGS 304UL
#define NACRE_SIGNAL_FP 560UL
#define NACRE_SIGNAL_DATA 64UL
/* Public control information only; no interrupted AU PC/GPR snapshot. */
struct nacre_signal_export {
    unsigned long frame, handler, size, signal;
};
#endif
