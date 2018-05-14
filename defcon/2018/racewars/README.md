# Racewars - 135pt

The binary has a bunch of functonality to outfit your car and modify those parts. No obvious bugs, the only one is we can pass an arbritrary size to the heap allocator when buying tires intially:

```c
puts("how many pairs of tires do you need?");
__isoc99_scanf("%d", &num_tires);
if ( num_tires <= 1 )
{
  puts("you need at least 4 tires to drive...");
  exit(1);
}
v6 = 32 * num_tires;                          // unbounded!!!!
v7 = (Tire *)heap_alloc(a1, 32 * num_tires);
```

The 32 * numTires is implemented as:

```assembly
mov     eax, [rbp+num_tires]
shl     eax, 5
```

The custom heap is implemented as a couple linked lists and some other weird stuff. The internals aren't important, but if we pass 0 as the size to the heap allocator we will get a pointer on the heap, and the next allocation will return that same pointer. So we get a type confusion that way. We send (2 << 33) >> 5 as our size to send 0 to the allocator.

With the modifyTires function we control the first 8 bytes of the Tire struct completely. Modify transmission has the following code:
```c
  printf("ok, you have a transmission with %zu gears\n", a1->num_gears);
  printf("which gear to modify? ");
  __isoc99_scanf("%zu", &v2);
  if ( a1->num_gears > (unsigned __int64)--v2 )
  {
    printf("gear ratio for gear %zu is %zu, modify to what?: ", v2 + 1, (unsigned __int8)a1->gears[v2]);
    v4 = v2;
    __isoc99_scanf("%zu", &v2);
    printf("set gear to %d\n? (1 = yes, 0 = no)", v2);
    __isoc99_scanf("%zu", &v3);
    if ( v3 )
      a1->gears[v4] = v2;                       // relative write if choice unbounded
  }
```

Transmission is defined as:
```
00000000 Transmission    struc ; (sizeof=0x18, mappedto_6)
00000000 num_gears       dq ?
00000008 type            db ?
00000009 gears           db 15 dup(?)
00000018 Transmission    ends
```

So we use the type confusion to set num gears to 2^64, and then use the relative read and write to leak a pointer on the heap, and resolve that to get an arbritrary r/w. Then we leak a libc address from the PLT and write a magic gadget to exit()
