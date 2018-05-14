# It's-a me! (mario) - 124 points

When cooking a pizza, you can provide an explanation which is allocated on the heap with the length of your explanation:

```c
printf("Before I start cooking your pizzas, do you have anything to declare? Please explain: ");
read_len(src, 300LL);
v1 = strlen(src);
a1->explanation = (char *)malloc(v1 + 1);
strcpy(a1->explanation, src);
```

But if we make Mario upset we can do an overflow on the heap:
```assembly
lea     rdi, aLastChanceExpl ; "last chance, explain yourself: "
mov     eax, 0
call    printf
lea     rax, cur_customer
mov     rax, [rax]
mov     rax, [rax+20h] ; explanation
mov     esi, 300
mov     rdi, rax
call    read_len
```

To reach this code path we need to make a pizza with pineapple in it (ingredients are UTF-8 emojis), without actually adding a pineapple as an ingredient. The way it checks is it strcats the ingredients together and calls strstr with the pineapple emoji to check, so we can create two adjacent ingredients, one which has the first two bytes of the pineapple at the end and one which has the second two bytes at the beginning. It only accepts UTF-8 as ingredients, so we need to prefix the first part of the pineapple emoji with \xe0 to get it to accept that.

There is also a use after free:
```c
if ( v15 >> 4 == (v14 & 0xF) )              // if # of pizzas == number of tomato pizzas
    {
	puts("Molto bene, all cooked!");
	if ( !(v15 & 0xF) )                       // if no pineapple pizzas
		free(a1->explanation);
```

We can leak a heap pointer this way. In order to do that we need to have the number of tomato pizzas be the number of pizzas, and have no pineapple pizzas. But we need to have at least one pineapple pizza to see explanation and get the leak. Thankfully the binary uses 4 bit counters so we can send 16 pineapple pizzas and one tomato pizza and the check will pass.

With the heap address we can do an arbritray read on the heap (binary has PIE), by grooming the heap so that the allocated explanation comes directly before the customer instance that Mario is upset with. Grooming the heap for this is super annoying and took me a few hours of trial and error but I eventually got it right. I found a random pointer on the heap that pointed to something in libc (think it was a main arena pointer or something).

We can also get arbritrary code execution by grooming the heap so that a pizza vtable pointer is after our allocated explanation. Thankfully this groom was much easier to achieve. We set the vtable pointer to point to an address on the heap we control, and put a magic gadget in there.

I'm wondering if this challenge had another bug in it that I missed, as the heap grooming took me several hours to do (although this was the first time I've done heap grooming).
