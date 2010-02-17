#include <asm/types.h>
#include <asm/div64.h>

#if BITS_PER_LONG == 32

u64 __udivdi3(u64 a, u64 b)
{
  do_div(a, b);
  return a;
}

u64 __umoddi3(u64 a, u64 b)
{
  return do_div(a, b);
}
#endif
